package corpus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/vendora-bit/pg-kms-gateway/internal/policy"
	"github.com/vendora-bit/pg-kms-gateway/internal/querymap"
)

const Version = 1

type Document struct {
	Version    int         `json:"version"`
	Profile    string      `json:"profile"`
	Statements []Statement `json:"statements"`
}

type Statement struct {
	Name             string `json:"name"`
	SQL              string `json:"sql"`
	Expected         string `json:"expected"`
	TouchesProtected bool   `json:"touchesProtected"`
}

type Report struct {
	Total     int
	Supported int
	Rejected  int
	Failed    int
}

func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("corpus: read %s: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("corpus: decode: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return Document{}, errors.New("corpus: multiple JSON values are not allowed")
	}
	if document.Version != Version || document.Profile == "" || len(document.Statements) == 0 {
		return Document{}, errors.New("corpus: version, profile and at least one statement are required")
	}
	seen := make(map[string]struct{}, len(document.Statements))
	for index, statement := range document.Statements {
		if statement.Name == "" || statement.SQL == "" || (statement.Expected != "supported" && statement.Expected != "rejected") {
			return Document{}, fmt.Errorf("corpus: statement %d has invalid name, SQL or expected outcome", index)
		}
		if _, duplicate := seen[statement.Name]; duplicate {
			return Document{}, fmt.Errorf("corpus: duplicate statement name %q", statement.Name)
		}
		seen[statement.Name] = struct{}{}
	}
	return document, nil
}

func Verify(document Document, catalog *policy.Catalog) (Report, error) {
	if catalog == nil {
		return Report{}, errors.New("corpus: policy catalog is required")
	}
	report := Report{Total: len(document.Statements)}
	var failures []error
	for _, statement := range document.Statements {
		plan, err := querymap.Analyze(statement.SQL, catalog)
		supported := err == nil
		if supported {
			report.Supported++
		} else {
			report.Rejected++
		}
		if (statement.Expected == "supported") != supported {
			report.Failed++
			failures = append(failures, fmt.Errorf("%s: expected %s, got %v", statement.Name, statement.Expected, err))
			continue
		}
		if supported && plan.TouchesProtectedData != statement.TouchesProtected {
			report.Failed++
			failures = append(failures, fmt.Errorf("%s: protected-data classification mismatch", statement.Name))
		}
	}
	return report, errors.Join(failures...)
}
