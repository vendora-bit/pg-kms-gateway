package querymap

import (
	"errors"
	"fmt"

	pgquery "github.com/pganalyze/pg_query_go/v6"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
)

var ErrUnsafeQuery = errors.New("querymap: query cannot be transformed safely")

type Operation string

const (
	EncryptRandom        Operation = "encrypt-random"
	EncryptDeterministic Operation = "encrypt-deterministic"
	ComputeBlindIndex    Operation = "blind-index"
)

type ParameterRule struct {
	Source int
	Target int
	Op     Operation
	Field  policy.Field
	KeyID  string
}

type ResultRule struct {
	Ordinal int
	Field   policy.Field
}

type Plan struct {
	SQL                    string
	OriginalParameterCount int
	ParameterCount         int
	Parameters             []ParameterRule
	Results                []ResultRule
	ResolveResultOrigins   bool
	TouchesProtectedData   bool
}

func Analyze(sql string, catalog *policy.Catalog) (Plan, error) {
	return AnalyzeWithKeyIDs(sql, catalog, nil)
}

func AnalyzeWithKeyIDs(sql string, catalog *policy.Catalog, keyIDs []string) (Plan, error) {
	if catalog == nil {
		return Plan{}, errors.New("querymap: policy catalog is required")
	}
	tree, err := pgquery.Parse(sql)
	if err != nil {
		return Plan{}, fmt.Errorf("querymap: parse SQL: %w", err)
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return Plan{}, fmt.Errorf("%w: exactly one statement is required", ErrUnsafeQuery)
	}
	count := maxParameter(tree.ProtoReflect())
	if len(keyIDs) == 0 {
		keyIDs = []string{""}
	}
	if len(keyIDs) > 32 {
		return Plan{}, fmt.Errorf("%w: more than 32 searchable key versions require re-encryption", ErrUnsafeQuery)
	}
	planner := &planner{catalog: catalog, tree: tree, keyIDs: append([]string(nil), keyIDs...), nextParameter: count, plan: Plan{SQL: sql, OriginalParameterCount: count, ParameterCount: count}}
	stmt := tree.Stmts[0].Stmt
	switch {
	case stmt.GetInsertStmt() != nil:
		err = planner.insert(stmt.GetInsertStmt())
	case stmt.GetUpdateStmt() != nil:
		err = planner.update(stmt.GetUpdateStmt())
	case stmt.GetSelectStmt() != nil:
		err = planner.selectStatement(stmt.GetSelectStmt())
	case stmt.GetDeleteStmt() != nil:
		err = planner.deleteStatement(stmt.GetDeleteStmt())
	case stmt.GetMergeStmt() != nil:
		err = fmt.Errorf("%w: MERGE is not supported by the gateway", ErrUnsafeQuery)
	case stmt.GetCopyStmt() != nil:
		err = fmt.Errorf("%w: COPY is not supported by the gateway", ErrUnsafeQuery)
	case stmt.GetTransactionStmt() != nil, stmt.GetVariableSetStmt() != nil, stmt.GetVariableShowStmt() != nil:
		// Transaction control and session-local configuration carry no row data.
	default:
		err = fmt.Errorf("%w: statement type is not approved by the protected SQL policy", ErrUnsafeQuery)
	}
	if err != nil {
		return Plan{}, err
	}
	planner.plan.ParameterCount = planner.nextParameter
	if planner.modified {
		planner.plan.SQL, err = pgquery.Deparse(tree)
		if err != nil {
			return Plan{}, fmt.Errorf("querymap: deparse transformed SQL: %w", err)
		}
	}
	return planner.plan, nil
}

type planner struct {
	catalog       *policy.Catalog
	tree          *pgquery.ParseResult
	nextParameter int
	plan          Plan
	modified      bool
	keyIDs        []string
}

func (p *planner) insert(stmt *pgquery.InsertStmt) error {
	relation, fields, err := p.protectedRelation(stmt.Relation)
	if err != nil || len(fields) == 0 {
		return err
	}
	p.plan.TouchesProtectedData = true
	if stmt.WithClause != nil || stmt.OnConflictClause != nil {
		return fmt.Errorf("%w: WITH and ON CONFLICT on protected INSERT require an explicit safe form", ErrUnsafeQuery)
	}
	selectStmt := stmt.SelectStmt.GetSelectStmt()
	if selectStmt == nil || len(selectStmt.ValuesLists) == 0 || len(stmt.Cols) == 0 {
		return fmt.Errorf("%w: protected INSERT must use an explicit column list and VALUES", ErrUnsafeQuery)
	}
	columns := make([]string, len(stmt.Cols))
	columnFields := make([]*policy.Field, len(stmt.Cols))
	for i, node := range stmt.Cols {
		target := node.GetResTarget()
		if target == nil || target.Name == "" || len(target.Indirection) != 0 {
			return fmt.Errorf("%w: protected INSERT column list is ambiguous", ErrUnsafeQuery)
		}
		columns[i] = target.Name
		if field, ok := p.catalog.Lookup(policy.Identity{Schema: relation.Schema, Table: relation.Table, Column: target.Name}); ok {
			fieldCopy := field
			columnFields[i] = &fieldCopy
		}
	}
	for _, field := range columnFields {
		if field != nil && field.BlindIndex != "" {
			stmt.Cols = append(stmt.Cols, resTarget(field.BlindIndex, nil))
			p.modified = true
		}
	}
	for _, rowNode := range selectStmt.ValuesLists {
		row := rowNode.GetList()
		if row == nil || len(row.Items) != len(columns) {
			return fmt.Errorf("%w: protected INSERT VALUES shape is inconsistent", ErrUnsafeQuery)
		}
		for i, column := range columns {
			fieldPtr := columnFields[i]
			if fieldPtr == nil {
				continue
			}
			field := *fieldPtr
			parameter := directParameter(row.Items[i])
			if parameter == nil {
				return fmt.Errorf("%w: protected INSERT value for %s must be a bind parameter", ErrUnsafeQuery, column)
			}
			if err := p.addEncryption(int(parameter.Number), int(parameter.Number), field); err != nil {
				return err
			}
			if field.BlindIndex != "" {
				p.nextParameter++
				row.Items = append(row.Items, paramNode(p.nextParameter))
				if err := p.addRule(ParameterRule{Source: int(parameter.Number), Target: p.nextParameter, Op: ComputeBlindIndex, Field: field}); err != nil {
					return err
				}
			}
		}
	}
	return p.results(relation, stmt.ReturningList)
}

func (p *planner) update(stmt *pgquery.UpdateStmt) error {
	relation, fields, err := p.protectedRelation(stmt.Relation)
	if err != nil || len(fields) == 0 {
		return err
	}
	p.plan.TouchesProtectedData = true
	if stmt.WithClause != nil || len(stmt.FromClause) != 0 {
		return fmt.Errorf("%w: WITH and UPDATE FROM on protected relations are ambiguous", ErrUnsafeQuery)
	}
	for _, node := range stmt.TargetList {
		target := node.GetResTarget()
		if target == nil || target.Name == "" || len(target.Indirection) != 0 {
			return fmt.Errorf("%w: protected UPDATE target is ambiguous", ErrUnsafeQuery)
		}
		field, ok := p.catalog.Lookup(policy.Identity{Schema: relation.Schema, Table: relation.Table, Column: target.Name})
		if !ok {
			continue
		}
		parameter := directParameter(target.Val)
		if parameter == nil {
			return fmt.Errorf("%w: protected UPDATE value for %s must be a bind parameter", ErrUnsafeQuery, target.Name)
		}
		if err := p.addEncryption(int(parameter.Number), int(parameter.Number), field); err != nil {
			return err
		}
		if field.BlindIndex != "" {
			p.nextParameter++
			stmt.TargetList = append(stmt.TargetList, resTarget(field.BlindIndex, paramNode(p.nextParameter)))
			if err := p.addRule(ParameterRule{Source: int(parameter.Number), Target: p.nextParameter, Op: ComputeBlindIndex, Field: field}); err != nil {
				return err
			}
			p.modified = true
		}
	}
	if err := p.where(relation, stmt.WhereClause); err != nil {
		return err
	}
	return p.results(relation, stmt.ReturningList)
}

func (p *planner) selectStatement(stmt *pgquery.SelectStmt) error {
	if stmt.Op != pgquery.SetOperation_SETOP_NONE || stmt.WithClause != nil || len(stmt.FromClause) != 1 {
		if p.selectMayTouchProtected(stmt) {
			return fmt.Errorf("%w: protected SELECT must have one direct relation and no set operation", ErrUnsafeQuery)
		}
		return nil
	}
	rangeVar := stmt.FromClause[0].GetRangeVar()
	if rangeVar == nil {
		if p.selectMayTouchProtected(stmt) {
			return fmt.Errorf("%w: protected SELECT relation is nested or joined", ErrUnsafeQuery)
		}
		return nil
	}
	relation, fields, err := p.protectedRelation(rangeVar)
	if err != nil || len(fields) == 0 {
		return err
	}
	p.plan.TouchesProtectedData = true
	if stmt.IntoClause != nil {
		return fmt.Errorf("%w: SELECT INTO from protected data is forbidden", ErrUnsafeQuery)
	}
	if err := p.where(relation, stmt.WhereClause); err != nil {
		return err
	}
	return p.results(relation, stmt.TargetList)
}

func (p *planner) deleteStatement(stmt *pgquery.DeleteStmt) error {
	relation, fields, err := p.protectedRelation(stmt.Relation)
	if err != nil || len(fields) == 0 {
		return err
	}
	p.plan.TouchesProtectedData = true
	if stmt.WithClause != nil || len(stmt.UsingClause) != 0 {
		return fmt.Errorf("%w: protected DELETE WITH/USING is ambiguous", ErrUnsafeQuery)
	}
	if err := p.where(relation, stmt.WhereClause); err != nil {
		return err
	}
	return p.results(relation, stmt.ReturningList)
}

type relationID struct{ Schema, Table, Qualifier string }

func (p *planner) protectedRelation(rv *pgquery.RangeVar) (relationID, []policy.Field, error) {
	if rv == nil || rv.Relname == "" || rv.Catalogname != "" {
		return relationID{}, nil, nil
	}
	schema := rv.Schemaname
	if schema == "" {
		schema = "public"
	}
	fields := p.catalog.Table(schema, rv.Relname)
	qualifier := rv.Relname
	if rv.Alias != nil && rv.Alias.Aliasname != "" {
		qualifier = rv.Alias.Aliasname
	}
	return relationID{Schema: schema, Table: rv.Relname, Qualifier: qualifier}, fields, nil
}

func (p *planner) relationProtected(rv *pgquery.RangeVar) bool {
	_, fields, _ := p.protectedRelation(rv)
	return len(fields) > 0
}

func (p *planner) selectMayTouchProtected(stmt *pgquery.SelectStmt) bool {
	found := false
	var visit func(protoreflect.Message)
	visit = func(message protoreflect.Message) {
		if found {
			return
		}
		if relation, ok := message.Interface().(*pgquery.RangeVar); ok && p.relationProtected(relation) {
			found = true
			return
		}
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.IsList() && field.Kind() == protoreflect.MessageKind {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					visit(list.Get(i).Message())
				}
			} else if field.Kind() == protoreflect.MessageKind {
				visit(value.Message())
			}
			return !found
		})
	}
	visit(stmt.ProtoReflect())
	return found
}

func (p *planner) addEncryption(source, target int, field policy.Field) error {
	op := EncryptRandom
	if field.Mode == policy.ModeDeterministic {
		op = EncryptDeterministic
	}
	return p.addRule(ParameterRule{Source: source, Target: target, Op: op, Field: field, KeyID: p.keyIDs[0]})
}

func (p *planner) addRule(rule ParameterRule) error {
	if rule.Source <= 0 || rule.Source > p.plan.OriginalParameterCount || rule.Target <= 0 {
		return fmt.Errorf("%w: invalid bind parameter mapping", ErrUnsafeQuery)
	}
	for _, existing := range p.plan.Parameters {
		if existing.Target == rule.Target {
			if existing.Source == rule.Source && existing.Op == rule.Op && existing.KeyID == rule.KeyID && existing.Field.Schema == rule.Field.Schema && existing.Field.Table == rule.Field.Table && existing.Field.Column == rule.Field.Column {
				return nil
			}
			return fmt.Errorf("%w: parameter $%d requires incompatible transformations", ErrUnsafeQuery, rule.Target)
		}
	}
	p.plan.Parameters = append(p.plan.Parameters, rule)
	return nil
}

func (p *planner) where(relation relationID, node *pgquery.Node) error {
	if node == nil {
		return nil
	}
	if boolExpr := node.GetBoolExpr(); boolExpr != nil {
		if boolExpr.Boolop != pgquery.BoolExprType_AND_EXPR {
			if referencesProtected(node, relation, p.catalog) {
				return fmt.Errorf("%w: only AND-combined protected predicates are supported", ErrUnsafeQuery)
			}
			return nil
		}
		for _, arg := range boolExpr.Args {
			if err := p.where(relation, arg); err != nil {
				return err
			}
		}
		return nil
	}
	expr := node.GetAExpr()
	if expr == nil {
		if referencesProtected(node, relation, p.catalog) {
			return fmt.Errorf("%w: protected predicate expression is unsupported", ErrUnsafeQuery)
		}
		return nil
	}
	columnNode, parameterNode := expr.Lexpr, expr.Rexpr
	column := columnName(columnNode, relation)
	parameter := directParameter(parameterNode)
	if column == "" || parameter == nil {
		columnNode, parameterNode = expr.Rexpr, expr.Lexpr
		column = columnName(columnNode, relation)
		parameter = directParameter(parameterNode)
	}
	field, protected := p.catalog.Lookup(policy.Identity{Schema: relation.Schema, Table: relation.Table, Column: column})
	if !protected {
		if referencesProtected(node, relation, p.catalog) {
			return fmt.Errorf("%w: protected predicates require a direct column reference", ErrUnsafeQuery)
		}
		return nil
	}
	if !isEquality(expr) || parameter == nil {
		return fmt.Errorf("%w: protected predicates require direct equality with a bind parameter", ErrUnsafeQuery)
	}
	if len(field.JSONPaths) > 0 {
		return fmt.Errorf("%w: equality over partially encrypted JSON is not supported", ErrUnsafeQuery)
	}
	if field.Mode == policy.ModeDeterministic {
		return p.expandEquality(node, columnNode, parameterNode, parameter, field, EncryptDeterministic)
	}
	if field.BlindIndex == "" {
		return fmt.Errorf("%w: random field %s has no blind index", ErrUnsafeQuery, field.Column)
	}
	setColumnName(columnNode, field.BlindIndex)
	source := int(parameter.Number)
	target := int(parameter.Number)
	for _, existing := range p.plan.Parameters {
		if existing.Target == target && existing.Op != ComputeBlindIndex {
			p.nextParameter++
			target = p.nextParameter
			parameter.Number = int32(target)
			break
		}
	}
	p.modified = true
	if err := p.addRule(ParameterRule{Source: source, Target: target, Op: ComputeBlindIndex, Field: field, KeyID: p.keyIDs[0]}); err != nil {
		return err
	}
	return p.appendEqualityVersions(node, columnNode, parameterNode, source, field, ComputeBlindIndex)
}

func (p *planner) expandEquality(node, columnNode, parameterNode *pgquery.Node, parameter *pgquery.ParamRef, field policy.Field, operation Operation) error {
	source := int(parameter.Number)
	target := source
	for _, existing := range p.plan.Parameters {
		if existing.Target == target && (existing.Op != operation || existing.Field.Column != field.Column || existing.KeyID != p.keyIDs[0]) {
			p.nextParameter++
			target = p.nextParameter
			parameter.Number = int32(target)
			p.modified = true
			break
		}
	}
	if err := p.addRule(ParameterRule{Source: source, Target: target, Op: operation, Field: field, KeyID: p.keyIDs[0]}); err != nil {
		return err
	}
	return p.appendEqualityVersions(node, columnNode, parameterNode, source, field, operation)
}

func (p *planner) appendEqualityVersions(node, columnNode, firstParameter *pgquery.Node, source int, field policy.Field, operation Operation) error {
	if len(p.keyIDs) == 1 {
		return nil
	}
	firstColumn := proto.Clone(columnNode).(*pgquery.Node)
	arguments := []*pgquery.Node{equalityNode(firstColumn, firstParameter)}
	for _, keyID := range p.keyIDs[1:] {
		p.nextParameter++
		target := p.nextParameter
		arguments = append(arguments, equalityNode(proto.Clone(columnNode).(*pgquery.Node), paramNode(target)))
		if err := p.addRule(ParameterRule{Source: source, Target: target, Op: operation, Field: field, KeyID: keyID}); err != nil {
			return err
		}
	}
	node.Node = &pgquery.Node_BoolExpr{BoolExpr: &pgquery.BoolExpr{Boolop: pgquery.BoolExprType_OR_EXPR, Args: arguments, Location: -1}}
	p.modified = true
	return nil
}

func equalityNode(column, parameter *pgquery.Node) *pgquery.Node {
	return &pgquery.Node{Node: &pgquery.Node_AExpr{AExpr: &pgquery.A_Expr{
		Kind:  pgquery.A_Expr_Kind_AEXPR_OP,
		Name:  []*pgquery.Node{{Node: &pgquery.Node_String_{String_: &pgquery.String{Sval: "="}}}},
		Lexpr: column, Rexpr: parameter, Location: -1,
	}}}
}

func (p *planner) results(relation relationID, list []*pgquery.Node) error {
	for ordinal, node := range list {
		target := node.GetResTarget()
		if target == nil || target.Val == nil {
			return fmt.Errorf("%w: result projection is ambiguous", ErrUnsafeQuery)
		}
		if target.Val.GetColumnRef() != nil && isStar(target.Val.GetColumnRef()) {
			p.plan.ResolveResultOrigins = true
			continue
		}
		column := columnName(target.Val, relation)
		if column == "" {
			if referencesProtected(target.Val, relation, p.catalog) {
				return fmt.Errorf("%w: expression over protected result is forbidden", ErrUnsafeQuery)
			}
			continue
		}
		if field, ok := p.catalog.Lookup(policy.Identity{Schema: relation.Schema, Table: relation.Table, Column: column}); ok {
			p.plan.Results = append(p.plan.Results, ResultRule{Ordinal: ordinal, Field: field})
		}
	}
	return nil
}

func maxParameter(message protoreflect.Message) int {
	max := 0
	var visit func(protoreflect.Message)
	visit = func(current protoreflect.Message) {
		if string(current.Descriptor().FullName()) == "pg_query.ParamRef" {
			field := current.Descriptor().Fields().ByName("number")
			if field != nil && int(current.Get(field).Int()) > max {
				max = int(current.Get(field).Int())
			}
		}
		current.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.IsList() && field.Kind() == protoreflect.MessageKind {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					visit(list.Get(i).Message())
				}
			} else if field.Kind() == protoreflect.MessageKind {
				visit(value.Message())
			}
			return true
		})
	}
	visit(message)
	return max
}

func directParameter(node *pgquery.Node) *pgquery.ParamRef {
	if node == nil {
		return nil
	}
	if parameter := node.GetParamRef(); parameter != nil {
		return parameter
	}
	if cast := node.GetTypeCast(); cast != nil {
		return cast.Arg.GetParamRef()
	}
	return nil
}

func columnName(node *pgquery.Node, relation relationID) string {
	if node == nil || node.GetColumnRef() == nil {
		return ""
	}
	fields := node.GetColumnRef().Fields
	if len(fields) == 1 && fields[0].GetString_() != nil {
		return fields[0].GetString_().Sval
	}
	if len(fields) == 2 && fields[0].GetString_() != nil && fields[1].GetString_() != nil && fields[0].GetString_().Sval == relation.Qualifier {
		return fields[1].GetString_().Sval
	}
	if len(fields) == 3 && relation.Qualifier == relation.Table && fields[0].GetString_() != nil && fields[1].GetString_() != nil && fields[2].GetString_() != nil && fields[0].GetString_().Sval == relation.Schema && fields[1].GetString_().Sval == relation.Table {
		return fields[2].GetString_().Sval
	}
	return ""
}

func setColumnName(node *pgquery.Node, name string) {
	fields := node.GetColumnRef().Fields
	fields[len(fields)-1].GetString_().Sval = name
}

func isEquality(expr *pgquery.A_Expr) bool {
	return expr.Kind == pgquery.A_Expr_Kind_AEXPR_OP && len(expr.Name) == 1 && expr.Name[0].GetString_() != nil && expr.Name[0].GetString_().Sval == "="
}

func referencesProtected(node *pgquery.Node, relation relationID, catalog *policy.Catalog) bool {
	if node == nil {
		return false
	}
	found := false
	var visit func(protoreflect.Message)
	visit = func(message protoreflect.Message) {
		if found {
			return
		}
		if ref, ok := message.Interface().(*pgquery.ColumnRef); ok {
			wrapper := &pgquery.Node{Node: &pgquery.Node_ColumnRef{ColumnRef: ref}}
			name := columnName(wrapper, relation)
			if name == "" && len(ref.Fields) > 0 && ref.Fields[len(ref.Fields)-1].GetString_() != nil {
				name = ref.Fields[len(ref.Fields)-1].GetString_().Sval
			}
			if _, protected := catalog.Lookup(policy.Identity{Schema: relation.Schema, Table: relation.Table, Column: name}); protected {
				found = true
				return
			}
		}
		message.Range(func(field protoreflect.FieldDescriptor, value protoreflect.Value) bool {
			if field.IsList() && field.Kind() == protoreflect.MessageKind {
				list := value.List()
				for i := 0; i < list.Len(); i++ {
					visit(list.Get(i).Message())
				}
			} else if field.Kind() == protoreflect.MessageKind {
				visit(value.Message())
			}
			return !found
		})
	}
	visit(node.ProtoReflect())
	return found
}

func isStar(ref *pgquery.ColumnRef) bool {
	if ref == nil || len(ref.Fields) == 0 {
		return false
	}
	return ref.Fields[len(ref.Fields)-1].GetAStar() != nil
}

func paramNode(number int) *pgquery.Node {
	return &pgquery.Node{Node: &pgquery.Node_ParamRef{ParamRef: &pgquery.ParamRef{Number: int32(number), Location: -1}}}
}

func resTarget(name string, value *pgquery.Node) *pgquery.Node {
	return &pgquery.Node{Node: &pgquery.Node_ResTarget{ResTarget: &pgquery.ResTarget{Name: name, Val: value, Location: -1}}}
}
