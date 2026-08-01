package policy

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const APIVersion = "pgkms.dev/v1"

type Mode string

const (
	ModeRandom        Mode = "random"
	ModeDeterministic Mode = "deterministic"
)

type Normalizer string

const (
	NormalizeNone          Normalizer = "none"
	NormalizeTrim          Normalizer = "trim"
	NormalizeLowercaseTrim Normalizer = "lowercase-trim"
)

type Document struct {
	APIVersion string   `yaml:"apiVersion"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

type Metadata struct {
	Name string `yaml:"name"`
}

type Spec struct {
	KeyDomain string  `yaml:"keyDomain"`
	Columns   []Field `yaml:"columns"`
}

type Field struct {
	Schema      string     `yaml:"schema"`
	Table       string     `yaml:"table"`
	Column      string     `yaml:"column"`
	Mode        Mode       `yaml:"mode"`
	Normalize   Normalizer `yaml:"normalize,omitempty"`
	BlindIndex  string     `yaml:"blindIndex,omitempty"`
	JSONPaths   []string   `yaml:"jsonPaths,omitempty"`
	Description string     `yaml:"description,omitempty"`
}

type Identity struct {
	Schema string
	Table  string
	Column string
}

func (i Identity) String() string { return i.Schema + "." + i.Table + "." + i.Column }

var identifierPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_$]*$`)

func (d *Document) Validate() error {
	if d.APIVersion != APIVersion {
		return fmt.Errorf("policy: apiVersion must be %q", APIVersion)
	}
	if d.Kind != "FieldEncryptionPolicy" {
		return errors.New("policy: kind must be FieldEncryptionPolicy")
	}
	if !identifierPattern.MatchString(d.Metadata.Name) {
		return errors.New("policy: metadata.name must be a simple identifier")
	}
	if strings.TrimSpace(d.Spec.KeyDomain) == "" {
		return errors.New("policy: spec.keyDomain is required")
	}
	if len(d.Spec.Columns) == 0 {
		return errors.New("policy: at least one protected column is required")
	}

	seen := make(map[Identity]struct{}, len(d.Spec.Columns))
	blind := make(map[Identity]Identity)
	for n := range d.Spec.Columns {
		field := &d.Spec.Columns[n]
		if field.Schema == "" {
			field.Schema = "public"
		}
		if field.Mode == "" {
			field.Mode = ModeRandom
		}
		if field.Normalize == "" {
			field.Normalize = NormalizeNone
		}
		for label, value := range map[string]string{
			"schema": field.Schema,
			"table":  field.Table,
			"column": field.Column,
		} {
			if !identifierPattern.MatchString(value) {
				return fmt.Errorf("policy: columns[%d].%s is not a simple identifier", n, label)
			}
		}
		id := Identity{Schema: field.Schema, Table: field.Table, Column: field.Column}
		if _, duplicate := seen[id]; duplicate {
			return fmt.Errorf("policy: duplicate protected column %s", id)
		}
		seen[id] = struct{}{}

		switch field.Mode {
		case ModeRandom, ModeDeterministic:
		default:
			return fmt.Errorf("policy: %s has unsupported mode %q", id, field.Mode)
		}
		switch field.Normalize {
		case NormalizeNone, NormalizeTrim, NormalizeLowercaseTrim:
		default:
			return fmt.Errorf("policy: %s has unsupported normalizer %q", id, field.Normalize)
		}
		if field.Normalize != NormalizeNone && field.Mode == ModeRandom && field.BlindIndex == "" {
			return fmt.Errorf("policy: %s normalization would alter random plaintext without a search purpose", id)
		}
		if field.BlindIndex != "" {
			if !identifierPattern.MatchString(field.BlindIndex) {
				return fmt.Errorf("policy: %s blindIndex is not a simple identifier", id)
			}
			indexID := Identity{Schema: field.Schema, Table: field.Table, Column: field.BlindIndex}
			if owner, exists := blind[indexID]; exists {
				return fmt.Errorf("policy: blind-index column %s is shared by %s and %s", indexID, owner, id)
			}
			blind[indexID] = id
		}
		for _, path := range field.JSONPaths {
			if err := validateJSONPath(path); err != nil {
				return fmt.Errorf("policy: %s jsonPath %q: %w", id, path, err)
			}
		}
		if len(field.JSONPaths) > 0 && field.BlindIndex != "" {
			return fmt.Errorf("policy: %s cannot combine jsonPaths with a whole-column blind index", id)
		}
		if len(field.JSONPaths) > 0 && field.Normalize != NormalizeNone {
			return fmt.Errorf("policy: %s cannot normalize an entire JSON document", id)
		}
	}
	for indexID, owner := range blind {
		if _, protected := seen[indexID]; protected {
			return fmt.Errorf("policy: blind-index column %s for %s is also configured as protected", indexID, owner)
		}
	}
	return nil
}

func validateJSONPath(path string) error {
	if path == "$" {
		return errors.New("root selection is not allowed")
	}
	if !strings.HasPrefix(path, "$.") {
		return errors.New("must use a dotted path beginning with dollar-dot")
	}
	parts := strings.Split(strings.TrimPrefix(path, "$."), ".")
	if len(parts) > 16 {
		return errors.New("depth exceeds 16")
	}
	for _, part := range parts {
		if !identifierPattern.MatchString(part) {
			return errors.New("only dotted object keys are supported")
		}
	}
	return nil
}

type Catalog struct {
	domain  string
	byID    map[Identity]Field
	byTable map[[2]string][]Field
	all     []Field
	name    string
}

func Compile(doc Document) (*Catalog, error) {
	if err := doc.Validate(); err != nil {
		return nil, err
	}
	c := &Catalog{
		domain:  doc.Spec.KeyDomain,
		name:    doc.Metadata.Name,
		byID:    make(map[Identity]Field, len(doc.Spec.Columns)),
		byTable: make(map[[2]string][]Field),
		all:     append([]Field(nil), doc.Spec.Columns...),
	}
	for _, field := range doc.Spec.Columns {
		id := Identity{Schema: field.Schema, Table: field.Table, Column: field.Column}
		c.byID[id] = field
		key := [2]string{field.Schema, field.Table}
		c.byTable[key] = append(c.byTable[key], field)
	}
	for key := range c.byTable {
		sort.Slice(c.byTable[key], func(i, j int) bool {
			return c.byTable[key][i].Column < c.byTable[key][j].Column
		})
	}
	return c, nil
}

func (c *Catalog) Name() string      { return c.name }
func (c *Catalog) KeyDomain() string { return c.domain }

func (c *Catalog) Lookup(id Identity) (Field, bool) {
	field, ok := c.byID[id]
	return field, ok
}

func (c *Catalog) Table(schema, table string) []Field {
	return append([]Field(nil), c.byTable[[2]string{schema, table}]...)
}

func (c *Catalog) Fields() []Field { return append([]Field(nil), c.all...) }
