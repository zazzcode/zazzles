package langphp

import (
	"fmt"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// phpDep is one dependency path with its current protection class.
type phpDep struct {
	dep                               analysis.Dependency
	protection, container, key, entry string
	// regexGuard is the preg_match call whose capture this path reads, when
	// protection is phpRegexCapture.
	regexGuard analysis.Evidence
	// numeric is the analysis.CommandValue class of a path whose protection
	// is "numeric", and numericAt the check or conversion that made it so.
	numeric   string
	numericAt analysis.Evidence
	// authzProv, authzClass and authzSelecting ride a storage field from the
	// record that holds it. Only the authorization adapter reads them.
	authzProv      string
	authzClass     string
	authzSelecting []phpDep
}

// phpRegexCapture labels a path that is a capture group of a literal
// preg_match expression (close-findings-gaps D-4). Only command sinks read it
// (D-6); every other family treats it as unknown.
const phpRegexCapture = "regex_capture"

// phpRegex is the literal expression of a preg_match whose matches array a
// variable holds.
type phpRegex struct {
	pattern, flags, text string
	call                 analysis.Evidence
}

// phpLiteral is one finite literal candidate. More than one candidate means a
// value constrained to a finite alternative set (a security-level switch).
type phpLiteral struct {
	text      string
	condition []analysis.Evidence
}

type phpValue struct {
	configuration bool
	// superglobalFresh marks tracked request-element state that some joined
	// path left unwritten and unchecked: a read also yields fresh input.
	superglobalFresh bool
	deps             []phpDep
	gaps             []analysis.Gap
	literals         []phpLiteral
	constant         bool
	fields           map[string]phpValue
	// binding labels tracked objects: db_connection, db_statement, db_result.
	binding string
	driver  string
	// class names the user class of a `new C` object (binding php_class).
	class string
	// regex is set on the matches array of a literal preg_match.
	regex *phpRegex
	// classDecl is the declaration of a `new C` object; props is its
	// property map (D-10). propsUnknown marks a write through a dynamic
	// property name: no property read is then established.
	classDecl    *phpClassDecl
	props        map[string]phpValue
	propsUnknown bool
	// objectID identifies one created object so aliases see its writes.
	objectID int
	// prefix is the literal text a concatenated string starts with.
	prefix string
	// table/columns carry SQL read provenance for storage linking.
	table   string
	columns []string
	// sqlText keeps the SQL text value on statements/results so a later
	// execute() re-records construction-time taint.
	sqlText *phpValue
	// sqlTextEvidence is the prepared SQL text operand of a statement, so
	// execute() supplies the statement it runs, not only its bindings.
	sqlTextEvidence []analysis.Evidence
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
	// diagnostic marks a value that carries internal state from a diagnostic
	// operation (exposure D-1). Only output sinks read it.
	diagnostic *phpDiagnostic
	// keySources are the request-key paths of a foreach key over a whole
	// request bag (mass-assignment D-7); keyGuards are key allow-lists applied
	// to the bag; wholeBag holds the request source of a bag value that has no
	// dependency of its own (Request::toArray). Only the mass-assignment
	// adapter reads them; no other claim's value changes.
	keySources []phpDep
	keyGuards  []analysis.Evidence
	wholeBag   []phpDep
	// reflection tags a value of a reflection object built over a stored
	// target: a ReflectionProperty whose construction named the property with
	// a request-chosen key, or a ReflectionClass over the target. The write
	// sink is the later setValue or getProperty call, so the construction only
	// tags the value. Only the mass-assignment adapter reads it.
	reflection *phpReflectionTarget
	// authz is the authorization subject of an entity object. The shared
	// doctrine object keeps it across branch joins; this pointer is the
	// copy on the value that created the object.
	authz *phpAuthz
	// secret marks a value derived from a generated secret (branch 3 D-5).
	// Only the recovery adapter reads it.
	secret *phpSecret
	// digest marks a value computed by one fast digest (branch 3 D-8).
	digest *phpDigest
}

// phpSideChannel reports a value carrying claim-specific side facts that the
// generic join must preserve but never treats as content.
func phpSideChannel(v phpValue) bool {
	return v.diagnostic != nil || v.reflection != nil || len(v.keySources) > 0 || len(v.keyGuards) > 0 || len(v.wholeBag) > 0 || v.authz != nil || v.secret != nil || v.digest != nil
}

// phpJoinSide joins two values with join after setting their side facts aside,
// then restores the union of the side facts on the result.
func phpJoinSide(a, b phpValue, join func(a, b phpValue) phpValue) phpValue {
	d := a.diagnostic
	if d == nil {
		d = b.diagnostic
	}
	r := a.reflection
	if r == nil {
		r = b.reflection
	}
	sources := phpMergeDeps(a.keySources, b.keySources)
	guards := phpMergeEvidence(a.keyGuards, b.keyGuards)
	bag := phpMergeDeps(a.wholeBag, b.wholeBag)
	az := a.authz
	if az == nil {
		az = b.authz
	}
	sec := a.secret
	if sec == nil {
		sec = b.secret
	}
	dg := a.digest
	if dg == nil {
		dg = b.digest
	}
	for _, v := range []*phpValue{&a, &b} {
		v.diagnostic, v.reflection, v.keySources, v.keyGuards, v.wholeBag, v.authz, v.secret, v.digest = nil, nil, nil, nil, nil, nil, nil, nil
	}
	out := join(a, b)
	out.authz = az
	out.secret = sec
	out.digest = dg
	out.diagnostic = d
	out.reflection = r
	if len(sources) > 0 {
		out.keySources = sources
	}
	if len(guards) > 0 {
		out.keyGuards = guards
	}
	if len(bag) > 0 {
		out.wholeBag = bag
	}
	return out
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
	if phpSideChannel(a) || phpSideChannel(b) {
		return phpJoinSide(a, b, phpCombine)
	}
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
	if a.classDecl != nil || b.classDecl != nil {
		// Object values join property by property; different classes are
		// no longer one object.
		if a.classDecl != b.classDecl {
			a.classDecl, a.props = nil, nil
		} else {
			a.props = phpJoinProps(a.props, b.props)
		}
		a.propsUnknown = a.propsUnknown || b.propsUnknown
	}
	return a
}

func phpJoinProps(a, b map[string]phpValue) map[string]phpValue {
	if a == nil && b == nil {
		return nil
	}
	out := map[string]phpValue{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if prior, ok := out[k]; ok {
			out[k] = phpJoin(prior, v)
		} else {
			out[k] = v
		}
	}
	return out
}

// phpJoin merges branch values: distinct protections on the same source stay
// separate dependency paths; literal candidate sets union with their conditions.
func phpJoin(a, b phpValue) phpValue {
	if phpSideChannel(a) || phpSideChannel(b) {
		return phpJoinSide(a, b, phpJoin)
	}
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
	seen := map[string]int{}
	for _, d := range append(append([]phpDep{}, a...), b...) {
		key := fmt.Sprintf("%v|%s|%s|%s|%s", d.dep.Source.Span, d.protection, d.container, d.key, d.dep.StorageKey)
		if i, ok := seen[key]; ok {
			// One path that joins differently checked numeric values holds
			// no single class of text.
			if out[i].numeric != d.numeric {
				out[i].numeric = ""
			}
			continue
		}
		seen[key] = len(out)
		out = append(out, d)
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

// phpConcatTransfer records a concatenation as a string_construction transfer,
// except on a path whose last transfer is the inner concatenation of the same
// left-nested template (same start): that innermost one already shows where
// the value lands, and each enclosing level would repeat the template from
// its start (judge evidence quality T).
func phpConcatTransfer(v phpValue, e analysis.Evidence) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		t := v.deps[i].dep.Transfers
		if n := len(t); n > 0 && t[n-1].Kind == "string_construction" && t[n-1].Span.File == e.Span.File && t[n-1].Span.StartByte == e.Span.StartByte {
			continue
		}
		one := phpTransfer(phpValue{deps: []phpDep{v.deps[i]}}, e)
		v.deps[i] = one.deps[0]
		v.gaps = append(v.gaps, one.gaps...)
	}
	return v
}

func phpProtect(v phpValue, p string) phpValue {
	v.deps = append([]phpDep{}, v.deps...)
	for i := range v.deps {
		v.deps[i].protection = p
		v.deps[i].numeric, v.deps[i].numericAt = "", analysis.Evidence{}
	}
	return v
}

// phpNumeric marks a value numeric and records which check or conversion at
// made it so, with the class of text that leaves.
func phpNumeric(v phpValue, class string, at analysis.Evidence) phpValue {
	v = phpProtect(v, "numeric")
	for i := range v.deps {
		v.deps[i].numeric, v.deps[i].numericAt = class, at
	}
	return v
}

// phpDigitsGuard is the branch-protection label of ctype_digit: a numeric
// protection whose value holds digits only.
const phpDigitsGuard = "numeric_digits"

// phpGuarded applies the protection a branch condition at implies.
func phpGuarded(v phpValue, protection string, at analysis.Evidence) phpValue {
	switch protection {
	case "numeric":
		return phpNumeric(v, analysis.CommandValueNumericString, at)
	case phpDigitsGuard:
		return phpNumeric(v, analysis.CommandValueDigits, at)
	}
	return phpProtect(v, protection)
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

func inertPHP(v phpValue) bool {
	return len(v.deps) == 0 && len(v.gaps) == 0 && v.fields == nil && v.binding == "" && v.class == "" && v.driver == "" && v.table == "" && v.columns == nil && v.sqlText == nil && v.sqlParams == nil && v.sqlWrites == nil && v.escapes == nil && v.bindingControls == nil && !v.unknown && !v.built
}

// phpPrefixOf returns the literal text a value starts with.
func phpPrefixOf(v phpValue) string {
	if v.constant && len(v.literals) == 1 && len(v.deps) == 0 {
		return v.literals[0].text
	}
	return v.prefix
}

func phpConstantText(v phpValue) bool {
	return v.constant && len(v.literals) == 1 && len(v.deps) == 0
}
