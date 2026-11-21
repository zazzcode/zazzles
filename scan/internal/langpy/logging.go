package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"regexp"
	"strings"
)

var pythonEmailLiteral = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)

func (f *pythonFlow) logValue(n *sitter.Node, v pythonValue) pythonValue {
	if v.constant && pythonEmailLiteral.MatchString(v.literal) {
		source := f.module.evidence("literal_sensitive_source", n)
		if len(v.evidence) > 0 {
			source = v.evidence[0]
			source.Kind = "literal_sensitive_source"
		}
		v.deps = append(v.deps, pythonDep{dep: analysis.Dependency{Source: source, Transfers: []analysis.Evidence{f.module.evidence("log_argument", n)}}, protection: "raw", container: "literal", key: "email"})
	}
	if v.binding == "db_row" && len(v.deps) == 0 {
		source := f.module.evidence("storage_source", n)
		if len(v.evidence) > 0 {
			source = v.evidence[len(v.evidence)-1]
			source.Kind = "storage_source"
		}
		v.deps = append(v.deps, pythonDep{dep: analysis.Dependency{Source: source, Transfers: append([]analysis.Evidence{}, v.evidence...)}, protection: "unknown", container: "body", key: ""})
	}
	for i := range v.deps {
		d := &v.deps[i]
		if d.dep.StorageKey != "" {
			parts := strings.Split(d.dep.StorageKey, ".")
			d.key = parts[len(parts)-1]
			d.container = "stored"
		}
	}
	return v
}
