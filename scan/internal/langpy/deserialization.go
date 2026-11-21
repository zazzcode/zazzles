package langpy

import (
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

func (f *pythonFlow) deserializationOperation(call, fn *sitter.Node, args []*sitter.Node, values []pythonValue) {
	m := f.module
	q := f.deserializationBinding(m, fn)
	lib, method, _ := strings.Cut(q, ".")
	facts := analysis.DeserializationFacts{Operation: q, Capability: analysis.DeserializationCodeExecution}
	var arg *sitter.Node
	var restriction analysis.Evidence
	var operand pythonValue
	if len(args) > 0 {
		arg, operand = args[0], values[0]
	}
	keyword := ""
	switch {
	case pythonPickleLibrary(lib) && (method == "load" || method == "loads"):
		facts.ContractID = analysispacks.PythonPickle
	case q == "jsonpickle.decode":
		facts.ContractID, keyword = analysispacks.PythonJSONPickle, "string"
	case lib == "yaml":
		facts.ContractID, keyword = analysispacks.PythonYAML, "stream"
		if !f.deserializationYAML(call, args, method, &facts) {
			return
		}
	case pyText(m, pyField(fn, "attribute")) == "load":
		constructor := pyField(fn, "object")
		if constructor == nil || constructor.Kind() != "call" {
			return
		}
		ctor := pyField(constructor, "function")
		name := f.deserializationBinding(m, ctor)
		lib, op, _ := strings.Cut(name, ".")
		if !pythonPickleLibrary(lib) || op != "Unpickler" {
			className := pyText(m, ctor)
			var ok bool
			restriction, ok = f.pickleSubclass(ctor, className)
			if !ok {
				return
			}
			name = className
		}
		ctorArgs := pyArgs(constructor)
		if len(ctorArgs) == 0 {
			return
		}
		arg, operand = ctorArgs[0], f.quiet(ctorArgs[0])
		facts.Operation, facts.ContractID = name+".load", analysispacks.PythonPickle
	default:
		return
	}
	if arg == nil && keyword != "" {
		arg = pyKeywordIn(m, call, keyword)
		if arg != nil {
			operand = f.quiet(arg)
		}
	}
	if len(operand.deps) == 0 {
		return
	}
	f.recordDeserialization(call, fn, arg, operand, facts, restriction)
}

func (f *pythonFlow) pickleSubclass(ctor *sitter.Node, name string) (analysis.Evidence, bool) {
	m := f.module
	root, _, _ := strings.Cut(name, ".")
	if _, local := f.env[root]; local || ctor == nil || f.set.staticInvalid[m.file+":"+root] {
		return analysis.Evidence{}, false
	}
	target, key := f.set.resolve(m, name, 0)
	if target == nil || f.set.staticInvalid[target.file+":"+key] {
		return analysis.Evidence{}, false
	}
	class := target.vars[key]
	if class == nil || class.Kind() != "class_definition" {
		return analysis.Evidence{}, false
	}
	bases := pyField(class, "superclasses")
	if bases == nil || bases.NamedChildCount() != 1 {
		return analysis.Evidence{}, false
	}
	base := pyText(target, bases.NamedChild(0))
	baseRoot, _, _ := strings.Cut(base, ".")
	if f.set.qualified(target, base) != "pickle.Unpickler" ||
		f.set.staticInvalid[target.file+":"+baseRoot] && pythonDeserializerReassigned(target, baseRoot) {
		return analysis.Evidence{}, false
	}
	body := pyField(class, "body")
	var restriction analysis.Evidence
	if body == nil {
		return restriction, false
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt.Kind() == "decorated_definition" {
			stmt = pyField(stmt, "definition")
		}
		if stmt == nil || stmt.Kind() != "function_definition" {
			continue
		}
		switch pyText(target, pyField(stmt, "name")) {
		case "load":
			return analysis.Evidence{}, false
		case "find_class":
			restriction = target.evidence("deserialization_class_restriction", stmt)
		}
	}
	return restriction, true
}

func pythonPickleLibrary(name string) bool {
	switch name {
	case "pickle", "_pickle", "cPickle", "dill", "cloudpickle":
		return true
	}
	return false
}

func (f *pythonFlow) deserializationBinding(m *pythonModule, n *sitter.Node) string {
	name := pyText(m, n)
	root, _, _ := strings.Cut(name, ".")
	if f.set.staticInvalid[m.file+":"+root] && pythonDeserializerReassigned(m, root) {
		return ""
	}
	if m == f.module {
		return f.qualifiedRaw(name)
	}
	return f.set.qualified(m, name)
}

// The static registry index is intentionally name-based across scopes. A
// local assignment in another callable cannot replace a module import.
func pythonDeserializerReassigned(m *pythonModule, root string) bool {
	if m.bindingIndex().aliased[root] || m.vars[root] != nil {
		return true
	}
	reassigned := false
	pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
		left := pyField(n, "left")
		if left == nil || n.Kind() != "assignment" && n.Kind() != "augmented_assignment" {
			return
		}
		name := pyText(m, left)
		if strings.HasPrefix(name, root+".") || strings.HasPrefix(name, root+"[") {
			reassigned = true
		}
		if name == root {
			for p := n.Parent(); p != nil; p = p.Parent() {
				if p.Kind() == "function_definition" || p.Kind() == "class_definition" {
					return
				}
			}
			reassigned = true
		}
	})
	return reassigned
}

func (f *pythonFlow) deserializationYAML(call *sitter.Node, args []*sitter.Node, method string, facts *analysis.DeserializationFacts) bool {
	switch method {
	case "unsafe_load", "unsafe_load_all":
		return true
	case "full_load", "full_load_all":
		facts.Capability = analysis.DeserializationRestrictedTypes
		return true
	case "load", "load_all":
	default:
		return false
	}
	m := f.module
	loader := pyKeywordIn(m, call, "Loader")
	if loader == nil && len(args) > 1 {
		loader = args[1]
	}
	if loader != nil {
		facts.Option = pyText(m, loader)
		switch f.deserializationBinding(m, loader) {
		case "yaml.SafeLoader", "yaml.CSafeLoader", "yaml.BaseLoader", "yaml.CBaseLoader":
			return false
		case "yaml.UnsafeLoader", "yaml.CUnsafeLoader", "yaml.Loader", "yaml.CLoader":
		case "yaml.FullLoader", "yaml.CFullLoader":
			facts.Capability = analysis.DeserializationRestrictedTypes
		default:
			facts.Capability, facts.OptionGap = analysis.DeserializationUnresolved, "loader_unresolved"
		}
		return true
	}
	facts.Version = f.set.pyYAMLVersion(m.file)
	if facts.Version == "" {
		facts.Capability, facts.OptionGap = analysis.DeserializationUnresolved, "version_unknown"
		return true
	}
	parts := strings.Split(facts.Version, ".")
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	if major >= 6 {
		return false
	}
	if major == 5 && minor >= 1 {
		facts.Capability = analysis.DeserializationRestrictedTypes
	}
	return true
}

func (f *pythonFlow) recordDeserialization(call, fn, arg *sitter.Node, operand pythonValue, facts analysis.DeserializationFacts, restriction analysis.Evidence) {
	m := f.module
	u := f.addUse(analysis.DeserializationKind, call, operand)
	u.NoteDeserializationOrigin()
	u.Deserialization = &facts
	u.APIModel = analysispacks.DeserializationContract(facts.ContractID)
	u.Context = append(u.Context, m.evidence("sink_binding", fn))
	for i := range u.Dependencies {
		u.Dependencies[i].SinkSlot = "data"
		facts.Paths = append(facts.Paths, analysis.CommandPath{Dependency: i, Operand: "data"})
	}
	guards, indices, derived, names := f.pythonOperandGuards(u, call)
	f.completePythonOperandClaim(u, call, operand, guards, indices, derived, names, func(u *analysis.CandidateUse, extra map[string][]analysis.Evidence, blockers, coverage []analysis.Gap) *analysis.Completeness {
		var remaining []analysis.Gap
		for _, g := range blockers {
			if ev, ok := f.deserializationTransfer(g, u.Dependencies); ok {
				coverage = append(coverage, g)
				extra["transformation"] = append(extra["transformation"], ev)
			} else {
				remaining = append(remaining, g)
			}
		}
		c := parse.SSRFCompleteness(u, extra, remaining, coverage)
		c.ClaimKind = "deserialization"
		c.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "deserialization_operand"}
		c.Evidence["deserialization_operand"] = []analysis.Evidence{m.evidence("deserialization_operand", arg)}
		delete(c.Evidence, "destination_operand")
		c.Scope = "Verified deserializer and independent data operand paths."
		return c
	}, facts.Paths)
	for i, guard := range guards {
		facts.Controls = append(facts.Controls, analysis.DeserializationControl{Kind: f.deserializationGuard(guard), Context: indices[i]})
	}
	if restriction.Kind != "" {
		u.AddDeserializationClassRestriction(restriction)
	}
}

func (f *pythonFlow) deserializationTransfer(g analysis.Gap, deps []analysis.Dependency) (analysis.Evidence, bool) {
	m := f.set.modules[g.At.File]
	if m == nil || !touchesCommandDependency(g, deps) {
		return analysis.Evidence{}, false
	}
	n := parse.NodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if n == nil {
		return analysis.Evidence{}, false
	}
	switch g.Kind {
	case "python_call_unresolved", "python_dispatch_unresolved":
	case "python_value_unresolved":
		if n.Kind() != "identifier" {
			return analysis.Evidence{}, false
		}
		n = n.Parent()
		for n != nil && n.Kind() == "attribute" {
			n = n.Parent()
		}
	default:
		return analysis.Evidence{}, false
	}
	if n == nil || n.Kind() != "call" || !f.isDeserializationTransfer(m, pyField(n, "function")) {
		return analysis.Evidence{}, false
	}
	return m.evidence("content_preserving_transfer", n), true
}

func (f *pythonFlow) isDeserializationTransfer(m *pythonModule, fn *sitter.Node) bool {
	q := f.deserializationBinding(m, fn)
	switch q {
	case "io.BytesIO", "io.StringIO", "base64.b64decode", "base64.urlsafe_b64decode", "base64.b32decode", "base64.b16decode",
		"binascii.unhexlify", "binascii.a2b_base64", "zlib.decompress", "gzip.decompress", "bz2.decompress", "lzma.decompress",
		"urllib.parse.unquote", "urllib.parse.unquote_plus", "urllib.parse.unquote_to_bytes", "urllib.parse.parse_qs", "urllib.parse.parse_qsl":
		return true
	}
	name := pyText(m, fn)
	if m == f.module && (name == "bytes" || name == "bytes.fromhex") && f.builtin("bytes") {
		return true
	}
	switch pyText(m, pyField(fn, "attribute")) {
	case "encode", "decode", "read", "getvalue":
		return true
	}
	return false
}

func (f *pythonFlow) deserializationGuard(e analysis.Evidence) string {
	m := f.set.modules[e.Span.File]
	kind := analysis.DeserializationFormat
	if m == nil {
		return kind
	}
	n := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
	if n != nil && n.Kind() == "if_statement" {
		n = pyField(n, "condition")
	}
	if n == nil {
		return kind
	}
	pyWalk(n, func(child *sitter.Node) {
		if child.Kind() != "call" || kind == analysis.DeserializationIntegrity {
			return
		}
		q := f.deserializationBinding(m, pyField(child, "function"))
		switch q {
		case "hmac.compare_digest", "hmac.new", "hmac.digest", "django.core.signing.loads", "django.core.signing.unsign", "itsdangerous.loads", "itsdangerous.unsign":
			kind = analysis.DeserializationIntegrity
		default:
			if strings.HasPrefix(q, "hashlib.") {
				kind = analysis.DeserializationUnkeyedHash
			}
		}
	})
	return kind
}
