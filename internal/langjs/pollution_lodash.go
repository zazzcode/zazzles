package langjs

import (
	"path"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
	"github.com/zazzcode/zazzles/internal/parse"
)

type lodashWriteBinding struct {
	pkg, method, contract string
	modular               bool
	at                    *sitter.Node
}

func (f *flow) lodashPollutionCall(call, fn *sitter.Node, args []*sitter.Node, values []value, b lodashWriteBinding) {
	first, last, slot := 1, len(args), "source"
	if b.contract == analysispacks.LodashSet {
		slot = "path"
		if b.method == "zipObjectDeep" {
			first = 0
		}
		last = first + 1
	} else if b.method == "mergeWith" && len(args) > 2 && pollutionFunctionValue(f.module, args[len(args)-1]) {
		last--
	}
	if first >= last || last > len(args) || callHasSpread(call) {
		return
	}
	if !pollutionRequest(values[first:last]) {
		return
	}
	res := f.set.resolvePackage(f.module.file, b.pkg)
	blocked, status := lodashPollutionVersion(b, res.Version)
	if status == "excluded" {
		return
	}
	binding := []analysis.Evidence{f.module.evidence("sink_binding", fn), f.module.evidence("sink_binding", b.at)}
	facts := &analysis.PollutionFacts{Operation: b.pkg + "." + b.method, ContractID: b.contract, KeyOperand: slot, Package: b.pkg, Blocked: blocked}
	if status == "affected" {
		if e, ok := f.set.pollutionVersionEvidence(b.pkg, res); ok {
			binding = append(binding, e)
			facts.Version = res.Version
		}
	}
	var guard pollutionGuard
	if first > 0 && pollutionNullTarget(f.module, call, args[0]) {
		guard = pollutionGuard{kind: "null_prototype_root", evidence: []analysis.Evidence{f.module.evidence("key_guard", args[0])}}
	}
	operands := make([]pollutionOperand, 0, last-first)
	for i := first; i < last; i++ {
		operands = append(operands, pollutionOperand{node: args[i], value: values[i]})
	}
	f.recordPollution(call, 0, operands, facts, binding, guard)
}

var lodashWrites = map[string]string{
	"merge": analysispacks.LodashMerge, "mergeWith": analysispacks.LodashMerge, "defaultsDeep": analysispacks.LodashMerge,
	"set": analysispacks.LodashSet, "setWith": analysispacks.LodashSet, "zipObjectDeep": analysispacks.LodashSet,
}

func lodashWrite(m *sourceModule, fn *sitter.Node) (lodashWriteBinding, bool) {
	b, ok := lodashBinding(m, unwrapTS(fn), 0)
	if ok && b.contract != "" && b.method != "" {
		return b, true
	}
	return lodashWriteBinding{}, false
}

func lodashBinding(m *sourceModule, n *sitter.Node, depth int) (lodashWriteBinding, bool) {
	if n == nil || depth > 4 {
		return lodashWriteBinding{}, false
	}
	switch n.Kind() {
	case "identifier":
		name := n.Utf8Text(m.src)
		if m.bindingWrites().written[name] {
			return lodashWriteBinding{}, false
		}
		if !m.cachedShadowed(n, name) {
			if imp, ok := m.imports[name]; ok {
				return pollutionImport(imp)
			}
		}
		init := localInitializer(m, n, name)
		if init != nil && init.EndByte() < n.StartByte() && init.Parent().Kind() == "variable_declarator" {
			return lodashBinding(m, unwrapTS(init), depth+1)
		}
	case "member_expression", "subscript_expression":
		obj := n.ChildByFieldName("object")
		method := pollutionMemberName(n, m.src)
		if n.Kind() == "member_expression" {
			if p := n.ChildByFieldName("property"); p != nil {
				method = p.Utf8Text(m.src)
			}
		}
		if contract := lodashWrites[method]; contract != "" {
			if b, ok := lodashBinding(m, obj, depth+1); ok && b.method == "" {
				b.method, b.contract = method, contract
				return b, true
			}
		}
	case "call_expression":
		if pkg, member, ok := requireBinding(m, n); ok && pollutionGlobal(m, n, "require") {
			return pollutionImport(importBinding{pkg, member, n})
		}
	}
	return lodashWriteBinding{}, false
}

func pollutionImport(imp importBinding) (lodashWriteBinding, bool) {
	b := lodashWriteBinding{pkg: imp.module, at: imp.declaration}
	switch {
	case imp.module == "lodash":
		if imp.name == "default" || imp.name == "*" {
			return b, true
		}
		b.method = imp.name
	case strings.HasPrefix(imp.module, "lodash/") && (imp.name == "default" || imp.name == "*"):
		b.pkg, b.method, b.modular = "lodash", strings.TrimPrefix(imp.module, "lodash/"), true
	case strings.HasPrefix(imp.module, "lodash.") && (imp.name == "default" || imp.name == "*"):
		for method := range lodashWrites {
			if strings.TrimPrefix(imp.module, "lodash.") == strings.ToLower(method) {
				b.method = method
				break
			}
		}
	}
	b.contract = lodashWrites[b.method]
	return b, b.contract != ""
}

func pollutionMemberName(n *sitter.Node, src []byte) string {
	name, _ := stringLiteral(n.ChildByFieldName("index"), src)
	return name
}

func pollutionBindingWritten(m *sourceModule, fn *sitter.Node) bool {
	if fn.Kind() == "member_expression" {
		fn = fn.ChildByFieldName("object")
	}
	return fn != nil && m.bindingWrites().written[fn.Utf8Text(m.src)]
}

func pollutionFunctionValue(m *sourceModule, n *sitter.Node) bool {
	n = unwrapTS(n)
	if n == nil {
		return false
	}
	if isFunction(n) {
		return true
	}
	if n.Kind() != "identifier" {
		return false
	}
	name := n.Utf8Text(m.src)
	if bindingReassigned(m, name) {
		return false
	}
	if init := localInitializer(m, n, name); init != nil {
		return isFunction(unwrapTS(init))
	}
	return m.funcs[name] != nil && !m.cachedShadowed(n, name)
}

func lodashPollutionVersion(b lodashWriteBinding, version string) ([]string, string) {
	v, ok := exactVersion(version)
	if !ok {
		return nil, "unresolved"
	}
	if b.contract == analysispacks.LodashMerge {
		return lodashMergeVersion(b, v)
	}
	if b.pkg != "lodash" {
		// The advisory verifies the released versions of the standalone set packages.
		// Versions outside its listed ranges require separate package evidence.
		switch b.pkg {
		case "lodash.zipobjectdeep":
			if !versionLess(v, [3]int{4, 18, 0}) {
				return nil, "excluded"
			}
			return nil, "affected"
		case "lodash.set":
			if !versionLess(v, [3]int{3, 7, 0}) && !versionLess([3]int{4, 3, 2}, v) {
				return nil, "affected"
			}
		case "lodash.setwith":
			if !versionLess([3]int{4, 3, 2}, v) {
				return nil, "affected"
			}
		}
		return nil, "unresolved"
	}
	// GHSA-p6mc-m468-83gw covers lodash from 3.7.0. The 4.17.19
	// monolith has the fix, but the release notes only verify refreshed
	// modular method files by 4.17.20.
	if versionLess(v, [3]int{3, 7, 0}) || !versionLess(v, [3]int{4, 17, 20}) {
		return nil, "excluded"
	}
	if v == [3]int{4, 17, 19} {
		if b.modular {
			return nil, "unresolved"
		}
		return nil, "excluded"
	}
	return nil, "affected"
}

func lodashMergeVersion(b lodashWriteBinding, v [3]int) ([]string, string) {
	if b.pkg != "lodash" {
		fixed := [3]int{4, 6, 2}
		if b.method == "defaultsDeep" {
			fixed = [3]int{4, 6, 1}
		}
		if versionLess(v, fixed) {
			return nil, "affected"
		}
		return nil, "excluded"
	}
	if versionLess(v, [3]int{4, 17, 5}) {
		return nil, "affected"
	}
	fixed := [3]int{4, 17, 11}
	if b.method == "defaultsDeep" {
		fixed = [3]int{4, 17, 12}
	}
	if versionLess(v, fixed) {
		return []string{"__proto__"}, "affected"
	}
	return nil, "excluded"
}

func (s *moduleSet) pollutionVersionEvidence(pkg string, res packageResolution) (analysis.Evidence, bool) {
	e, ok := s.readBounded(res.File, maxPackageFileBytes)
	if !ok {
		return analysis.Evidence{}, false
	}
	name, version := regexp.QuoteMeta(pkg), regexp.QuoteMeta(res.Version)
	var stanza string
	switch path.Base(res.File) {
	case "package.json":
		stanza = `"` + name + `"\s*:\s*"` + version + `"`
	case "package-lock.json", "npm-shrinkwrap.json":
		stanza = `"(?:[^"\n]*/node_modules/|node_modules/)?` + name + `"\s*:\s*\{[^{}]{0,1000}?"version"\s*:\s*"` + version + `"`
	case "pnpm-lock.yaml":
		stanza = `(?m)^\s*['"]?` + name + `['"]?:\s*(?:[^\n]*\n\s*specifier:[^\n]*\n\s*version:\s*)?['"]?` + version + `(?:[\s'"(]|$)`
	case "yarn.lock":
		stanza = `(?m)^"?` + name + `@[^\n]*\n(?:(?:  [^\n]+)\n){0,3}?  version[: ]+["']?` + version + `(?:["'\s]|$)`
	default:
		return analysis.Evidence{}, false
	}
	span := regexp.MustCompile(stanza).FindStringIndex(e.Text)
	if span == nil {
		return analysis.Evidence{}, false
	}
	return parse.TextRange(e, span[0], span[1], "dependency_version"), true
}

func pollutionNullTarget(m *sourceModule, at, arg *sitter.Node) bool {
	n := unwrapTS(arg)
	if n == nil {
		return false
	}
	if n.Kind() == "identifier" {
		name := n.Utf8Text(m.src)
		if bindingReassigned(m, name) {
			return false
		}
		n = unwrapTS(localInitializer(m, at, name))
	}
	if n == nil || n.Kind() != "call_expression" || n.EndByte() > at.EndByte() {
		return false
	}
	fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
	return fn != nil && fn.Utf8Text(m.src) == "Object.create" && pollutionBuiltin(m, n, "Object", "create") &&
		args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Kind() == "null"
}
