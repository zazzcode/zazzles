package cli

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func loadChecks(path string) ([]analysis.Check, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64<<10 {
		return nil, errors.New("checks file exceeds 64 KiB")
	}
	var checks []analysis.Check
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&checks); err != nil {
		return nil, err
	}
	if dec.Decode(new(any)) != io.EOF {
		return nil, errors.New("trailing data in checks file")
	}
	var raw []map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for i := range checks {
		c := &checks[i]
		_, hasMethod := raw[i]["method"]
		_, hasPath := raw[i]["path"]
		if c.Selector != nil && (hasMethod || hasPath) {
			return nil, errors.New("check must use selector or legacy method/path, never both")
		}
		selector := c.NormalizedSelector()
		if err := selector.Validate(); err != nil {
			return nil, err
		}
		c.Selector = &selector
		c.Method = ""
		c.Path = ""
		if c.ID == "" || ids[c.ID] || len(c.Fields) == 0 || c.Validation == "" || c.Protection == "" || (c.Kind != "sql_query" && c.Kind != "nosql_query" && c.Kind != "account_creation") {
			return nil, errors.New("invalid or duplicate check; require id, a valid selector, kind, fields and explicit requirements")
		}
		ids[c.ID] = true
	}
	if len(checks) == 0 || len(checks) > 20 {
		return nil, errors.New("checks file must contain 1 to 20 checks")
	}
	return checks, nil
}
