package pgsession

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/querymap"
	"github.com/vendora-bit/pg-kms-gateway/internal/recordcrypt"
	"github.com/vendora-bit/pg-kms-gateway/internal/telemetry"
)

var ErrProtocolSafety = errors.New("pgsession: protocol operation is unsafe for protected data")

type OriginResolver interface {
	Resolve(tableOID uint32, attributeNumber uint16) (policy.Field, bool, error)
}

type Machine struct {
	catalog    *policy.Catalog
	keyring    *recordcrypt.Keyring
	domain     string
	origins    OriginResolver
	metrics    *telemetry.Metrics
	statements map[string]*plannedObject
	portals    map[string]*plannedObject
	responses  []responseState
}

type plannedObject struct {
	plan    querymap.Plan
	results *resultMetadata
}

type resultMetadata struct {
	rules    []querymap.ResultRule
	resolved bool
}

type responseKind uint8

const (
	responseParse responseKind = iota + 1
	responseBind
	responseDescribeStatement
	responseDescribePortal
	responseExecute
	responseSimpleQuery
	responseClose
	responseReady
)

type responseState struct {
	kind     responseKind
	object   *plannedObject
	rules    []querymap.ResultRule
	rollback func()
}

func New(catalog *policy.Catalog, keyring *recordcrypt.Keyring, origins OriginResolver, metricSet ...*telemetry.Metrics) (*Machine, error) {
	if catalog == nil || keyring == nil {
		return nil, errors.New("pgsession: catalog and keyring are required")
	}
	var metrics *telemetry.Metrics
	if len(metricSet) > 0 {
		metrics = metricSet[0]
	}
	return &Machine{
		catalog: catalog, keyring: keyring, domain: catalog.KeyDomain(), origins: origins,
		metrics: metrics, statements: make(map[string]*plannedObject), portals: make(map[string]*plannedObject),
	}, nil
}

func (m *Machine) Frontend(message pgproto3.FrontendMessage) (pgproto3.FrontendMessage, error) {
	switch msg := message.(type) {
	case *pgproto3.Parse:
		return m.parse(msg)
	case *pgproto3.Bind:
		return m.bind(msg)
	case *pgproto3.Describe:
		return m.describe(msg)
	case *pgproto3.Execute:
		return m.execute(msg)
	case *pgproto3.Query:
		return m.query(msg)
	case *pgproto3.Close:
		return m.close(msg)
	case *pgproto3.Sync:
		m.responses = append(m.responses, responseState{kind: responseReady})
		return message, nil
	default:
		return message, nil
	}
}

func (m *Machine) Backend(message pgproto3.BackendMessage) (pgproto3.BackendMessage, error) {
	switch msg := message.(type) {
	case *pgproto3.RowDescription:
		if err := m.rowDescription(msg); err != nil {
			return nil, err
		}
		return message, nil
	case *pgproto3.ParameterDescription:
		current, err := m.current(responseDescribeStatement)
		if err != nil {
			return nil, err
		}
		if len(msg.ParameterOIDs) != current.object.plan.ParameterCount {
			return nil, fmt.Errorf("%w: backend ParameterDescription does not match transformed plan", ErrProtocolSafety)
		}
		copyMessage := *msg
		copyMessage.ParameterOIDs = append([]uint32(nil), msg.ParameterOIDs[:current.object.plan.OriginalParameterCount]...)
		return &copyMessage, nil
	case *pgproto3.DataRow:
		current, err := m.currentExecution()
		if err != nil {
			return nil, err
		}
		protectedOrdinals := make(map[int]struct{}, len(current.rules))
		for _, rule := range current.rules {
			protectedOrdinals[rule.Ordinal] = struct{}{}
		}
		for ordinal, value := range msg.Values {
			if _, protected := protectedOrdinals[ordinal]; !protected && bytes.Contains(value, []byte(recordcrypt.Prefix)) {
				return nil, fmt.Errorf("%w: encrypted envelope appeared in an unproven result column", ErrProtocolSafety)
			}
		}
		if len(current.rules) == 0 {
			return message, nil
		}
		values, err := querymap.ApplyResults(current.rules, m.keyring, m.domain, msg.Values)
		if err != nil {
			return nil, fmt.Errorf("%w: decrypt backend row: %v", ErrProtocolSafety, err)
		}
		copyMessage := *msg
		copyMessage.Values = values
		return &copyMessage, nil
	case *pgproto3.ParseComplete:
		return message, m.complete(responseParse)
	case *pgproto3.BindComplete:
		return message, m.complete(responseBind)
	case *pgproto3.CloseComplete:
		return message, m.complete(responseClose)
	case *pgproto3.NoData:
		if len(m.responses) == 0 || (m.responses[0].kind != responseDescribeStatement && m.responses[0].kind != responseDescribePortal) {
			return nil, fmt.Errorf("%w: unexpected NoData", ErrProtocolSafety)
		}
		m.responses = m.responses[1:]
		return message, nil
	case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse, *pgproto3.PortalSuspended:
		if err := m.completeExecution(); err != nil {
			return nil, err
		}
		return message, nil
	case *pgproto3.ErrorResponse:
		m.failUntilReady()
		return message, nil
	case *pgproto3.ReadyForQuery:
		return message, m.complete(responseReady)
	default:
		return message, nil
	}
}

func (m *Machine) parse(msg *pgproto3.Parse) (pgproto3.FrontendMessage, error) {
	plan, err := querymap.AnalyzeWithKeyIDs(msg.Query, m.catalog, m.keyring.KeyIDs())
	if err != nil {
		return nil, err
	}
	m.observePlan(plan)
	if len(msg.ParameterOIDs) != 0 && len(msg.ParameterOIDs) != plan.OriginalParameterCount {
		return nil, fmt.Errorf("%w: Parse parameter OID count does not match SQL", ErrProtocolSafety)
	}
	copyMessage := *msg
	copyMessage.Query = plan.SQL
	copyMessage.ParameterOIDs = append([]uint32(nil), msg.ParameterOIDs...)
	for len(copyMessage.ParameterOIDs) > 0 && len(copyMessage.ParameterOIDs) < plan.ParameterCount {
		copyMessage.ParameterOIDs = append(copyMessage.ParameterOIDs, 0)
	}
	name := msg.Name
	previous, existed := m.statements[name]
	object := &plannedObject{plan: plan, results: &resultMetadata{rules: append([]querymap.ResultRule(nil), plan.Results...), resolved: !plan.ResolveResultOrigins}}
	m.statements[name] = object
	m.responses = append(m.responses, responseState{kind: responseParse, object: object, rollback: func() {
		if existed {
			m.statements[name] = previous
		} else {
			delete(m.statements, name)
		}
	}})
	return &copyMessage, nil
}

func (m *Machine) bind(msg *pgproto3.Bind) (pgproto3.FrontendMessage, error) {
	statement, ok := m.statements[msg.PreparedStatement]
	if !ok {
		return nil, fmt.Errorf("%w: unknown prepared statement %q", ErrProtocolSafety, msg.PreparedStatement)
	}
	plan := statement.plan
	formats, err := expandFormats(msg.ParameterFormatCodes, plan.OriginalParameterCount)
	if err != nil {
		return nil, err
	}
	for _, rule := range plan.Parameters {
		if formats[rule.Source-1] != pgproto3.TextFormat {
			return nil, fmt.Errorf("%w: protected parameter $%d uses binary format", ErrProtocolSafety, rule.Source)
		}
	}
	resultFormats, err := resultFormats(msg.ResultFormatCodes, plan)
	if err != nil {
		return nil, err
	}
	parameters, err := querymap.ApplyParameters(plan, m.keyring, m.domain, msg.Parameters)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProtocolSafety, err)
	}
	if m.metrics != nil {
		m.metrics.ParametersTransformed.Add(uint64(len(plan.Parameters)))
	}
	copyMessage := *msg
	copyMessage.Parameters = parameters
	copyMessage.ParameterFormatCodes = append(formats, make([]int16, plan.ParameterCount-plan.OriginalParameterCount)...)
	copyMessage.ResultFormatCodes = resultFormats
	portalName := msg.DestinationPortal
	previous, existed := m.portals[portalName]
	portal := &plannedObject{plan: plan, results: statement.results}
	m.portals[portalName] = portal
	m.responses = append(m.responses, responseState{kind: responseBind, object: portal, rollback: func() {
		if existed {
			m.portals[portalName] = previous
		} else {
			delete(m.portals, portalName)
		}
	}})
	return &copyMessage, nil
}

func (m *Machine) describe(msg *pgproto3.Describe) (pgproto3.FrontendMessage, error) {
	var object *plannedObject
	var ok bool
	kind := responseDescribeStatement
	switch msg.ObjectType {
	case 'S':
		object, ok = m.statements[msg.Name]
	case 'P':
		object, ok = m.portals[msg.Name]
		kind = responseDescribePortal
	default:
		return nil, fmt.Errorf("%w: invalid Describe object type", ErrProtocolSafety)
	}
	if !ok {
		return nil, fmt.Errorf("%w: Describe references unknown object %q", ErrProtocolSafety, msg.Name)
	}
	m.responses = append(m.responses, responseState{kind: kind, object: object})
	return msg, nil
}

func (m *Machine) execute(msg *pgproto3.Execute) (pgproto3.FrontendMessage, error) {
	portal, ok := m.portals[msg.Portal]
	if !ok {
		return nil, fmt.Errorf("%w: Execute references unknown portal %q", ErrProtocolSafety, msg.Portal)
	}
	m.responses = append(m.responses, responseState{kind: responseExecute, object: portal})
	return msg, nil
}

func (m *Machine) query(msg *pgproto3.Query) (pgproto3.FrontendMessage, error) {
	plan, err := querymap.AnalyzeWithKeyIDs(msg.String, m.catalog, m.keyring.KeyIDs())
	if err != nil {
		return nil, err
	}
	m.observePlan(plan)
	if plan.OriginalParameterCount != 0 || len(plan.Parameters) != 0 {
		return nil, fmt.Errorf("%w: simple Query cannot transform bind parameters", ErrProtocolSafety)
	}
	copyMessage := *msg
	copyMessage.String = plan.SQL
	object := &plannedObject{plan: plan, results: &resultMetadata{rules: append([]querymap.ResultRule(nil), plan.Results...), resolved: !plan.ResolveResultOrigins}}
	m.responses = append(m.responses, responseState{kind: responseSimpleQuery, object: object, rules: append([]querymap.ResultRule(nil), plan.Results...)}, responseState{kind: responseReady})
	return &copyMessage, nil
}

func (m *Machine) close(msg *pgproto3.Close) (pgproto3.FrontendMessage, error) {
	switch msg.ObjectType {
	case 'S':
		name := msg.Name
		previous, existed := m.statements[name]
		delete(m.statements, name)
		m.responses = append(m.responses, responseState{kind: responseClose, rollback: func() {
			if existed {
				m.statements[name] = previous
			}
		}})
	case 'P':
		name := msg.Name
		previous, existed := m.portals[name]
		delete(m.portals, name)
		m.responses = append(m.responses, responseState{kind: responseClose, rollback: func() {
			if existed {
				m.portals[name] = previous
			}
		}})
	default:
		return nil, fmt.Errorf("%w: invalid Close object type", ErrProtocolSafety)
	}
	return msg, nil
}

func (m *Machine) rowDescription(description *pgproto3.RowDescription) error {
	if len(m.responses) == 0 {
		return fmt.Errorf("%w: unexpected RowDescription", ErrProtocolSafety)
	}
	current := &m.responses[0]
	if current.kind != responseDescribeStatement && current.kind != responseDescribePortal && current.kind != responseSimpleQuery && current.kind != responseExecute {
		return fmt.Errorf("%w: RowDescription does not match the pending protocol operation", ErrProtocolSafety)
	}
	plan := current.object.plan
	rules := append([]querymap.ResultRule(nil), plan.Results...)
	if plan.ResolveResultOrigins {
		if m.origins == nil {
			return fmt.Errorf("%w: result origin resolver is required for wildcard projection", ErrProtocolSafety)
		}
		seen := make(map[int]struct{}, len(rules))
		for _, rule := range rules {
			seen[rule.Ordinal] = struct{}{}
		}
		for ordinal, fieldDescription := range description.Fields {
			field, protected, err := m.origins.Resolve(fieldDescription.TableOID, fieldDescription.TableAttributeNumber)
			if err != nil {
				return fmt.Errorf("%w: resolve result origin: %v", ErrProtocolSafety, err)
			}
			if protected {
				if _, exists := seen[ordinal]; !exists {
					rules = append(rules, querymap.ResultRule{Ordinal: ordinal, Field: field})
				}
			}
		}
	}
	for _, rule := range rules {
		if rule.Ordinal < 0 || rule.Ordinal >= len(description.Fields) {
			return fmt.Errorf("%w: result plan does not match RowDescription", ErrProtocolSafety)
		}
		if description.Fields[rule.Ordinal].Format != pgproto3.TextFormat {
			return fmt.Errorf("%w: protected result column %d uses binary format", ErrProtocolSafety, rule.Ordinal)
		}
	}
	current.rules = append([]querymap.ResultRule(nil), rules...)
	current.object.results.rules = append([]querymap.ResultRule(nil), rules...)
	current.object.results.resolved = true
	if m.metrics != nil {
		m.metrics.ResultValuesDecrypted.Add(uint64(len(rules)))
	}
	if current.kind == responseDescribeStatement || current.kind == responseDescribePortal {
		m.responses = m.responses[1:]
	}
	return nil
}

func (m *Machine) observePlan(plan querymap.Plan) {
	if m.metrics != nil && plan.TouchesProtectedData {
		m.metrics.ProtectedStatements.Add(1)
	}
}

func (m *Machine) current(kind responseKind) (*responseState, error) {
	if len(m.responses) == 0 || m.responses[0].kind != kind {
		return nil, fmt.Errorf("%w: backend response does not match the pending protocol operation", ErrProtocolSafety)
	}
	return &m.responses[0], nil
}

func (m *Machine) currentExecution() (*responseState, error) {
	if len(m.responses) == 0 || (m.responses[0].kind != responseExecute && m.responses[0].kind != responseSimpleQuery) {
		return nil, fmt.Errorf("%w: DataRow has no matching execution", ErrProtocolSafety)
	}
	current := &m.responses[0]
	if current.object.plan.ResolveResultOrigins && !current.object.results.resolved {
		return nil, fmt.Errorf("%w: wildcard result metadata was not proven before DataRow", ErrProtocolSafety)
	}
	if current.rules == nil {
		current.rules = append([]querymap.ResultRule(nil), current.object.results.rules...)
	}
	return current, nil
}

func (m *Machine) complete(kind responseKind) error {
	current, err := m.current(kind)
	if err != nil {
		return err
	}
	current.rollback = nil
	m.responses = m.responses[1:]
	return nil
}

func (m *Machine) completeExecution() error {
	if len(m.responses) == 0 || (m.responses[0].kind != responseExecute && m.responses[0].kind != responseSimpleQuery) {
		return fmt.Errorf("%w: result completion has no matching execution", ErrProtocolSafety)
	}
	m.responses = m.responses[1:]
	return nil
}

func (m *Machine) failUntilReady() {
	boundary := len(m.responses)
	for index, response := range m.responses {
		if response.kind == responseReady {
			boundary = index
			break
		}
	}
	for index := boundary - 1; index >= 0; index-- {
		if m.responses[index].rollback != nil {
			m.responses[index].rollback()
		}
	}
	if boundary == len(m.responses) {
		m.responses = nil
		return
	}
	m.responses = m.responses[boundary:]
}

func expandFormats(input []int16, count int) ([]int16, error) {
	switch len(input) {
	case 0:
		return make([]int16, count), nil
	case 1:
		output := make([]int16, count)
		for i := range output {
			output[i] = input[0]
		}
		return output, nil
	case count:
		return append([]int16(nil), input...), nil
	default:
		return nil, fmt.Errorf("%w: invalid parameter format-code count", ErrProtocolSafety)
	}
}

func resultFormats(input []int16, plan querymap.Plan) ([]int16, error) {
	if len(input) == 0 {
		return nil, nil
	}
	if len(input) == 1 {
		if input[0] == pgproto3.BinaryFormat && (len(plan.Results) > 0 || plan.ResolveResultOrigins) {
			return nil, fmt.Errorf("%w: protected results cannot use binary format", ErrProtocolSafety)
		}
		return append([]int16(nil), input...), nil
	}
	for _, rule := range plan.Results {
		if rule.Ordinal >= len(input) || input[rule.Ordinal] != pgproto3.TextFormat {
			return nil, fmt.Errorf("%w: protected result column %d cannot use binary format", ErrProtocolSafety, rule.Ordinal)
		}
	}
	if plan.ResolveResultOrigins {
		for _, format := range input {
			if format != pgproto3.TextFormat {
				return nil, fmt.Errorf("%w: wildcard protected results require text format", ErrProtocolSafety)
			}
		}
	}
	return append([]int16(nil), input...), nil
}
