package parse

import (
	"fmt"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// phpDep is one dependency path with its current protection class.
type phpDep struct {
	dep                               analysis.Dependency
	protection, container, key, entry string
}

// phpLiteral is one finite literal candidate. More than one candidate means a
// value constrained to a finite alternative set (a security-level switch).
type phpLiteral struct {
	text      string
	condition []analysis.Evidence
}

type phpValue struct {
	deps     []phpDep
	gaps     []analysis.Gap
	literals []phpLiteral
	constant bool
	fields   map[string]phpValue
	// binding labels tracked objects: db_connection, db_statement, db_result.
	binding string
	driver  string
	// class names the user class of a `new C` object (binding php_class).
	class string
	// table/columns carry SQL read provenance for storage linking.
	table   string
	columns []string
	// sqlText keeps the SQL text value on statements/results so a later
	// execute() re-records construction-time taint.
	sqlText *phpValue
	// sqlParams collects values bound through bindParam/bindValue so execute()
	// records the parameter operands with their binding controls.
	sqlParams []phpValue
	// template keeps the raw source template of an interpolated/concatenated
	// string (variables in place) for SQL table/column attribution.
	template string
	// sqlWrites keeps each INSERT/UPDATE template this value was built from,
	// with its interpolated dependencies in order, so stored-field writes
	// stay attributable after branch joins replace the single template.
	sqlWrites []phpSQLWrite
	// arrayLiterals keeps the string elements of an array literal whose
	// elements are all plain string literals (membership allowlists).
	arrayLiterals []string
	// escapes records htmlspecialchars/htmlentities transform evidence.
	escapes []analysis.Evidence
	// bindingControls records prepare/bindParam control evidence.
	bindingControls []analysis.Evidence
	evidence        []analysis.Evidence
	built           bool
	unknown         bool
}

// phpSQLWrite is one write-statement template with its interpolated deps.
type phpSQLWrite struct {
	template string
	deps     []phpDep
}

func phpEmpty(v phpValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && len(v.literals) == 0 && v.binding == "" && len(v.evidence) == 0 && len(v.escapes) == 0 && !v.built && !v.unknown && len(v.bindingControls) == 0
}

func phpCombine(a, b phpValue) phpValue {
	if phpEmpty(a) {
		return b
	}
	if phpEmpty(b) {
		return a
	}
	if len(a.literals) == 1 && len(b.literals) == 1 && a.constant && b.constant {
		a.literals = []phpLiteral{{text: a.literals[0].text + b.literals[0].text}}
	} else {
		a.constant = false
		a.literals = nil
	}
	if len(b.deps) > 0 || len(b.literals) > 0 {
		a.binding = ""
		a.class = ""
		a.table = ""
		a.columns = nil
	}
	a.unknown = a.unknown || b.unknown
	a.deps = phpMergeDeps(a.deps, b.deps)
	if len(a.deps) > 64 {
		a.deps = a.deps[:64]
		a.gaps = append(a.gaps, analysis.Gap{Kind: "dependency_limit", Detail: "PHP value exceeds 64 dependency paths", At: a.deps[0].dep.Source.Span})
	}
	a.gaps = append(append([]analysis.Gap{}, a.gaps...), b.gaps...)
	a.built = a.built || b.built
	a.escapes = append(append([]analysis.Evidence{}, a.escapes...), b.escapes...)
	a.bindingControls = append(append([]analysis.Evidence{}, a.bindingControls...), b.bindingControls...)
	a.evidence = append(append([]analysis.Evidence{}, a.evidence...), b.evidence...)
	a.sqlWrites = append(append([]phpSQLWrite{}, a.sqlWrites...), b.sqlWrites...)
	if a.fields == nil {
		a.fields = b.fields
	}
	return a
}

// phpJoin merges branch values: distinct protections on the same source stay
// separate dependency paths; literal candidate sets union with their conditions.
func phpJoin(a, b phpValue) phpValue {
	if phpEmpty(a) {
		return b
	}
	if phpEmpty(b) {
		return a
	}
	out := phpCombine(a, b)
	out.deps = phpMergeDeps(a.deps, b.deps)
	out.literals = append(append([]phpLiteral{}, a.literals...), b.literals...)
	out.constant = false
	if len(a.literals) == 1 && len(b.literals) == 1 && a.literals[0].text == b.literals[0].text {
		out.literals = []phpLiteral{a.literals[0]}
		out.constant = true
	}
	if len(out.literals) > 16 {
		out.literals = out.literals[:16]
	}
	return out
}

func phpMergeDeps(a, b []phpDep) []phpDep {
	out := []phpDep{}
	seen := map[string]bool{}
	for _, d := range append(append([]phpDep{}, a...), b...) {
		key := fmt.Sprintf("%v|%s|%s|%s|%s", d.dep.Source.Span, d.protection, d.container, d.key, d.dep.StorageKey)
		if !seen[key] {
			seen[key] = true
			out = append(out, d)
		}
	}
	return out
}

func phpTransfer(v phpValue, e analysis.Evidence) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].dep.Transfers = append(append([]analysis.Evidence{}, v.deps[i].dep.Transfers...), e)
		if len(v.deps[i].dep.Transfers) > 48 {
			v.deps[i].dep.Transfers = v.deps[i].dep.Transfers[:48]
			v.gaps = append(v.gaps, analysis.Gap{Kind: "transfer_limit", Detail: "PHP path exceeds 48 transfers", At: e.Span})
		}
	}
	return v
}

func phpProtect(v phpValue, p string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].protection = p
	}
	return v
}

func phpSlot(v phpValue, slot string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].dep.SinkSlot = slot
	}
	return v
}

// phpLiteralsOnly reports a value that is exactly a finite literal candidate
// set with no other content.
func phpLiteralsOnly(v phpValue) bool {
	return len(v.deps) == 0 && len(v.literals) > 0 && !v.unknown && len(v.gaps) == 0
}

func sliceFrom(values []phpValue, i int) phpValue {
	var v phpValue
	for ; i < len(values); i++ {
		v = phpCombine(v, values[i])
	}
	return v
}

// phpUnion concatenates lists keeping the first occurrence of each item by
// content. Branch clones inherit the parent's gaps and helper clones the
// caller's context, so a plain append would double the list at every
// conditional or helper call and inflate requests with duplicates.
func phpUnion[T comparable](lists ...[]T) []T {
	n := 0
	for _, l := range lists {
		n += len(l)
	}
	out := make([]T, 0, n)
	seen := make(map[T]bool, n)
	for _, l := range lists {
		for _, item := range l {
			if !seen[item] {
				seen[item] = true
				out = append(out, item)
			}
		}
	}
	return out
}

func phpMergeGaps(a, b []analysis.Gap) []analysis.Gap { return phpUnion(a, b) }

func phpMergeEvidence(a, b []analysis.Evidence) []analysis.Evidence { return phpUnion(a, b) }

func phpDedupeEvidence(list []analysis.Evidence) []analysis.Evidence { return phpUnion(list) }
