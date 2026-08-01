package origin

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
)

type Column struct {
	Schema          string
	Table           string
	Column          string
	TableOID        uint32
	AttributeNumber uint16
	TypeName        string
}

type Resolver struct {
	fields map[[2]uint32]policy.Field
}

func (r *Resolver) Resolve(tableOID uint32, attributeNumber uint16) (policy.Field, bool, error) {
	if r == nil {
		return policy.Field{}, false, errors.New("origin: resolver is nil")
	}
	field, ok := r.fields[[2]uint32{tableOID, uint32(attributeNumber)}]
	return field, ok, nil
}

func Compile(catalog *policy.Catalog, columns []Column) (*Resolver, error) {
	if catalog == nil {
		return nil, errors.New("origin: policy catalog is required")
	}
	metadata := make(map[policy.Identity]Column, len(columns))
	for _, column := range columns {
		id := policy.Identity{Schema: column.Schema, Table: column.Table, Column: column.Column}
		if _, duplicate := metadata[id]; duplicate {
			return nil, fmt.Errorf("origin: duplicate metadata for %s", id)
		}
		if column.TableOID == 0 || column.AttributeNumber == 0 || column.TypeName == "" {
			return nil, fmt.Errorf("origin: incomplete metadata for %s", id)
		}
		metadata[id] = column
	}
	resolved := &Resolver{fields: make(map[[2]uint32]policy.Field, len(catalog.Fields()))}
	for _, field := range catalog.Fields() {
		id := policy.Identity{Schema: field.Schema, Table: field.Table, Column: field.Column}
		column, ok := metadata[id]
		if !ok {
			return nil, fmt.Errorf("origin: protected column %s does not exist", id)
		}
		if err := compatibleType(field, column.TypeName); err != nil {
			return nil, fmt.Errorf("origin: %s: %w", id, err)
		}
		key := [2]uint32{column.TableOID, uint32(column.AttributeNumber)}
		if previous, duplicate := resolved.fields[key]; duplicate {
			return nil, fmt.Errorf("origin: OID mapping collision between %s.%s.%s and %s", previous.Schema, previous.Table, previous.Column, id)
		}
		resolved.fields[key] = field
		if field.BlindIndex != "" {
			indexID := policy.Identity{Schema: field.Schema, Table: field.Table, Column: field.BlindIndex}
			indexColumn, exists := metadata[indexID]
			if !exists {
				return nil, fmt.Errorf("origin: blind-index column %s does not exist", indexID)
			}
			if !isTextType(indexColumn.TypeName) {
				return nil, fmt.Errorf("origin: blind-index column %s has incompatible type %s", indexID, indexColumn.TypeName)
			}
		}
	}
	return resolved, nil
}

func Discover(ctx context.Context, connection *pgx.Conn, catalog *policy.Catalog) (*Resolver, error) {
	if connection == nil {
		return nil, errors.New("origin: PostgreSQL connection is required")
	}
	tables := make(map[[2]string]struct{})
	for _, field := range catalog.Fields() {
		tables[[2]string{field.Schema, field.Table}] = struct{}{}
	}
	tableList := make([][2]string, 0, len(tables))
	for table := range tables {
		tableList = append(tableList, table)
	}
	sort.Slice(tableList, func(i, j int) bool {
		return tableList[i][0]+"."+tableList[i][1] < tableList[j][0]+"."+tableList[j][1]
	})
	columns := make([]Column, 0)
	for _, table := range tableList {
		rows, err := connection.Query(ctx, `
SELECT n.nspname, c.relname, a.attname, c.oid, a.attnum, t.typname
FROM pg_catalog.pg_class AS c
JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid
JOIN pg_catalog.pg_type AS t ON t.oid = a.atttypid
WHERE n.nspname = $1 AND c.relname = $2
  AND c.relkind IN ('r', 'p') AND a.attnum > 0 AND NOT a.attisdropped
ORDER BY a.attnum`, table[0], table[1])
		if err != nil {
			return nil, fmt.Errorf("origin: inspect %s.%s: %w", table[0], table[1], err)
		}
		for rows.Next() {
			var column Column
			var attribute int16
			if err := rows.Scan(&column.Schema, &column.Table, &column.Column, &column.TableOID, &attribute, &column.TypeName); err != nil {
				rows.Close()
				return nil, fmt.Errorf("origin: scan %s.%s metadata: %w", table[0], table[1], err)
			}
			if attribute <= 0 {
				rows.Close()
				return nil, errors.New("origin: PostgreSQL returned invalid attribute number")
			}
			column.AttributeNumber = uint16(attribute)
			columns = append(columns, column)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("origin: read %s.%s metadata: %w", table[0], table[1], err)
		}
		rows.Close()
	}
	return Compile(catalog, columns)
}

func compatibleType(field policy.Field, typeName string) error {
	typeName = strings.ToLower(typeName)
	if len(field.JSONPaths) > 0 {
		if typeName != "json" && typeName != "jsonb" {
			return fmt.Errorf("jsonPaths require json or jsonb, got %s", typeName)
		}
		return nil
	}
	if !isTextType(typeName) {
		return fmt.Errorf("field encryption requires a text-compatible type, got %s", typeName)
	}
	return nil
}

func isTextType(typeName string) bool {
	switch strings.ToLower(typeName) {
	case "text", "varchar", "bpchar", "citext":
		return true
	default:
		return false
	}
}
