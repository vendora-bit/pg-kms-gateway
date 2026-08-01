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
	statements map[string]querymap.Plan
	portals    map[string]querymap.Plan

	describePlan *querymap.Plan
	activePlan   *querymap.Plan
	activeRules  []querymap.ResultRule
	pending      []pendingChange
}

type pendingChange struct {
	kind     string
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
		metrics:    metrics,
		statements: make(map[string]querymap.Plan), portals: make(map[string]querymap.Plan),
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
		if m.describePlan == nil {
			return message, nil
		}
		if len(msg.ParameterOIDs) != m.describePlan.ParameterCount {
			return nil, fmt.Errorf("%w: backend ParameterDescription does not match transformed plan", ErrProtocolSafety)
		}
		copyMessage := *msg
		copyMessage.ParameterOIDs = append([]uint32(nil), msg.ParameterOIDs[:m.describePlan.OriginalParameterCount]...)
		return &copyMessage, nil
	case *pgproto3.DataRow:
		protectedOrdinals := make(map[int]struct{}, len(m.activeRules))
		for _, rule := range m.activeRules {
			protectedOrdinals[rule.Ordinal] = struct{}{}
		}
		for ordinal, value := range msg.Values {
			if _, protected := protectedOrdinals[ordinal]; !protected && bytes.Contains(value, []byte(recordcrypt.Prefix)) {
				return nil, fmt.Errorf("%w: encrypted envelope appeared in an unproven result column", ErrProtocolSafety)
			}
		}
		if len(m.activeRules) == 0 {
			return message, nil
		}
		values, err := querymap.ApplyResults(m.activeRules, m.keyring, m.domain, msg.Values)
		if err != nil {
			return nil, fmt.Errorf("%w: decrypt backend row: %v", ErrProtocolSafety, err)
		}
		copyMessage := *msg
		copyMessage.Values = values
		return &copyMessage, nil
	case *pgproto3.ParseComplete:
		if err := m.commit("parse"); err != nil {
			return nil, err
		}
		return message, nil
	case *pgproto3.BindComplete:
		if err := m.commit("bind"); err != nil {
			return nil, err
		}
		return message, nil
	case *pgproto3.CloseComplete:
		if err := m.commit("close"); err != nil {
			return nil, err
		}
		return message, nil
	case *pgproto3.CommandComplete, *pgproto3.EmptyQueryResponse:
		m.finishResult()
		return message, nil
	case *pgproto3.ErrorResponse:
		m.rollbackPending()
		m.finishResult()
		m.describePlan = nil
		return message, nil
	case *pgproto3.ReadyForQuery:
		if len(m.pending) != 0 {
			m.rollbackPending()
			return nil, fmt.Errorf("%w: backend reached ReadyForQuery with unconfirmed protocol changes", ErrProtocolSafety)
		}
		m.finishResult()
		m.describePlan = nil
		return message, nil
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
	m.statements[name] = plan
	m.pending = append(m.pending, pendingChange{kind: "parse", rollback: func() {
		if existed {
			m.statements[name] = previous
		} else {
			delete(m.statements, name)
		}
	}})
	return &copyMessage, nil
}

func (m *Machine) bind(msg *pgproto3.Bind) (pgproto3.FrontendMessage, error) {
	plan, ok := m.statements[msg.PreparedStatement]
	if !ok {
		return nil, fmt.Errorf("%w: unknown prepared statement %q", ErrProtocolSafety, msg.PreparedStatement)
	}
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
	m.portals[portalName] = plan
	m.pending = append(m.pending, pendingChange{kind: "bind", rollback: func() {
		if existed {
			m.portals[portalName] = previous
		} else {
			delete(m.portals, portalName)
		}
	}})
	return &copyMessage, nil
}

func (m *Machine) describe(msg *pgproto3.Describe) (pgproto3.FrontendMessage, error) {
	var plan querymap.Plan
	var ok bool
	switch msg.ObjectType {
	case 'S':
		plan, ok = m.statements[msg.Name]
	case 'P':
		plan, ok = m.portals[msg.Name]
	default:
		return nil, fmt.Errorf("%w: invalid Describe object type", ErrProtocolSafety)
	}
	if !ok {
		return nil, fmt.Errorf("%w: Describe references unknown object %q", ErrProtocolSafety, msg.Name)
	}
	m.describePlan = &plan
	return msg, nil
}

func (m *Machine) execute(msg *pgproto3.Execute) (pgproto3.FrontendMessage, error) {
	plan, ok := m.portals[msg.Portal]
	if !ok {
		return nil, fmt.Errorf("%w: Execute references unknown portal %q", ErrProtocolSafety, msg.Portal)
	}
	m.activePlan = &plan
	m.activeRules = append([]querymap.ResultRule(nil), plan.Results...)
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
	m.activePlan = &plan
	m.activeRules = append([]querymap.ResultRule(nil), plan.Results...)
	return &copyMessage, nil
}

func (m *Machine) close(msg *pgproto3.Close) (pgproto3.FrontendMessage, error) {
	switch msg.ObjectType {
	case 'S':
		name := msg.Name
		previous, existed := m.statements[name]
		delete(m.statements, name)
		m.pending = append(m.pending, pendingChange{kind: "close", rollback: func() {
			if existed {
				m.statements[name] = previous
			}
		}})
	case 'P':
		name := msg.Name
		previous, existed := m.portals[name]
		delete(m.portals, name)
		m.pending = append(m.pending, pendingChange{kind: "close", rollback: func() {
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
	plan := m.activePlan
	if m.describePlan != nil {
		plan = m.describePlan
		m.describePlan = nil
	}
	if plan == nil {
		return nil
	}
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
	m.activeRules = rules
	if m.metrics != nil {
		m.metrics.ResultValuesDecrypted.Add(uint64(len(rules)))
	}
	return nil
}

func (m *Machine) observePlan(plan querymap.Plan) {
	if m.metrics != nil && plan.TouchesProtectedData {
		m.metrics.ProtectedStatements.Add(1)
	}
}

func (m *Machine) finishResult() {
	m.activePlan = nil
	m.activeRules = nil
}

func (m *Machine) commit(kind string) error {
	if len(m.pending) == 0 || m.pending[0].kind != kind {
		m.rollbackPending()
		return fmt.Errorf("%w: unexpected %s completion", ErrProtocolSafety, kind)
	}
	m.pending = m.pending[1:]
	return nil
}

func (m *Machine) rollbackPending() {
	for i := len(m.pending) - 1; i >= 0; i-- {
		m.pending[i].rollback()
	}
	m.pending = nil
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
