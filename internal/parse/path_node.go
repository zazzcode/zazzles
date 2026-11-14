package parse

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// nodeFSOps are the verified Node filesystem operations. The first argument is
// always the path; the second argument of the write forms is data written.
var nodeFSOps = map[string]struct {
	role  string
	write bool
	// promisesToo marks operations that also exist in fs/promises.
	promisesToo bool
}{
	"readFile":          {"read", false, true},
	"readFileSync":      {"read", false, false},
	"writeFile":         {"write", true, true},
	"writeFileSync":     {"write", true, false},
	"appendFile":        {"write", true, true},
	"appendFileSync":    {"write", true, false},
	"createReadStream":  {"read", false, false},
	"createWriteStream": {"write", false, false},
	"unlink":            {"delete", false, true},
	"unlinkSync":        {"delete", false, false},
	"rm":                {"delete", false, true},
	"rmSync":            {"delete", false, false},
}

func fsCoreModule(module string) (core, promises bool) {
	switch module {
	case "fs", "node:fs":
		return true, false
	case "fs/promises", "node:fs/promises":
		return true, true
	}
	return false, false
}

// readFSDestructuring records `const { readFile, writeFile: save } = require('fs')`.
func (m *sourceModule) readFSDestructuring(pattern, v, declaration *sitter.Node) {
	path, member, ok := requireBinding(m, v)
	if !ok || member != "*" {
		return
	}
	if core, _ := fsCoreModule(path); !core {
		return
	}
	for i := uint(0); i < pattern.NamedChildCount(); i++ {
		c := pattern.NamedChild(i)
		local, name := "", ""
		switch c.Kind() {
		case "shorthand_property_identifier_pattern":
			local = c.Utf8Text(m.src)
			name = local
		case "pair_pattern":
			key, value := c.ChildByFieldName("key"), c.ChildByFieldName("value")
			if key != nil && value != nil && value.Kind() == "identifier" {
				local, name = value.Utf8Text(m.src), key.Utf8Text(m.src)
			}
		}
		if local != "" && !bindingReassigned(m, local) {
			m.fsNames[local] = importBinding{path, name, declaration}
		}
	}
}

type fsBinding struct {
	op, label string
	promises  bool
	evidence  []analysis.Evidence
}

// fsMember resolves the called function to a member of the Node fs core
// module (or fs/promises) without choosing which members are modeled. Only an
// actual import or require of the core module, unshadowed and never
// reassigned, is verified; a fake object, a local module or a wrapper is not.
func fsMember(m *sourceModule, call, fn *sitter.Node) (fsBinding, bool) {
	found := func(op string, promises bool, evidence ...*sitter.Node) (fsBinding, bool) {
		label := "fs"
		if promises {
			label = "fs/promises"
		}
		b := fsBinding{op: op, label: label, promises: promises}
		for _, n := range evidence {
			b.evidence = append(b.evidence, m.evidence("sink_binding", n))
		}
		return b, true
	}
	switch fn.Kind() {
	case "identifier":
		name := fn.Utf8Text(m.src)
		if shadowed(call, name, m.src) || bindingReassigned(m, name) {
			return fsBinding{}, false
		}
		var b importBinding
		if imp, ok := m.imports[name]; ok && imp.name != "*" && imp.name != "default" && imp.name != "promises" {
			b = imp
		} else if imp, ok := m.fsNames[name]; ok {
			b = imp
		} else {
			return fsBinding{}, false
		}
		core, promises := fsCoreModule(b.module)
		if !core {
			return fsBinding{}, false
		}
		return found(b.name, promises, b.declaration, fn)
	case "member_expression":
		obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
		if obj == nil || prop == nil {
			return fsBinding{}, false
		}
		op := prop.Utf8Text(m.src)
		switch obj.Kind() {
		case "identifier":
			name := obj.Utf8Text(m.src)
			imp, ok := m.imports[name]
			if !ok || shadowed(call, name, m.src) || bindingReassigned(m, name) {
				return fsBinding{}, false
			}
			core, promises := fsCoreModule(imp.module)
			if !core {
				return fsBinding{}, false
			}
			if imp.name == "promises" && !promises {
				// import { promises as fsp } from 'fs' or const fsp = require('fs').promises
				return found(op, true, imp.declaration, fn)
			}
			if imp.name != "*" && imp.name != "default" {
				return fsBinding{}, false
			}
			return found(op, promises, imp.declaration, fn)
		case "member_expression":
			// fs.promises.readFile
			inner, member := obj.ChildByFieldName("object"), obj.ChildByFieldName("property")
			if inner == nil || member == nil || member.Utf8Text(m.src) != "promises" {
				return fsBinding{}, false
			}
			if inner.Kind() == "identifier" {
				name := inner.Utf8Text(m.src)
				imp, ok := m.imports[name]
				if !ok || shadowed(call, name, m.src) || bindingReassigned(m, name) || (imp.name != "*" && imp.name != "default") {
					return fsBinding{}, false
				}
				if core, promises := fsCoreModule(imp.module); !core || promises {
					return fsBinding{}, false
				}
				return found(op, true, imp.declaration, fn)
			}
			if inner.Kind() == "call_expression" {
				if path, mem, ok := requireBinding(m, inner); ok && mem == "*" {
					if core, promises := fsCoreModule(path); core && !promises {
						return found(op, true, inner, fn)
					}
				}
			}
		case "call_expression":
			if path, member, ok := requireBinding(m, obj); ok && member == "*" {
				if core, promises := fsCoreModule(path); core {
					return found(op, promises, obj, fn)
				}
			}
		}
	}
	return fsBinding{}, false
}

// nodeFSBinding resolves a modeled read/write operation of the Node fs module.
func (f *flow) nodeFSBinding(call, fn *sitter.Node) (fsBinding, bool) {
	b, ok := fsMember(f.module, call, fn)
	if !ok {
		return fsBinding{}, false
	}
	spec, known := nodeFSOps[b.op]
	if !known || (b.promises && !spec.promisesToo) {
		return fsBinding{}, false
	}
	return b, true
}

type jsPathBuilder struct {
	f       *flow
	facts   *analysis.PathFacts
	deps    []analysis.Dependency
	context []analysis.Evidence
	gaps    []analysis.Gap
	request bool
}

// operand records one slot. Only the path slot creates path flows; request
// data in the content slot is visible but is never a path source.
func (b *jsPathBuilder) operand(slot, kind string, n *sitter.Node, v value) {
	o := analysis.PathOperand{Slot: slot}
	if text, ok := stringLiteral(n, b.f.module.src); ok {
		o.Constant = text
	} else if n.Kind() != "string" {
		o.Dynamic = true
	}
	o.Context = append(o.Context, len(b.context))
	b.context = append(b.context, b.f.module.evidence(kind, n))
	for _, d := range v.deps {
		if (slot == analysis.PathSlotFile || slot == analysis.PathSlotArchive) && !requestOrigin(d) {
			// A stored, file, API or browser value is not a request field: second-order
			// flows need their own write-side evidence and are never invented here.
			continue
		}
		d.SinkSlot = slot
		idx := len(b.deps)
		o.Dependencies = append(o.Dependencies, idx)
		if slot == analysis.PathSlotFile || slot == analysis.PathSlotArchive {
			b.facts.Paths = append(b.facts.Paths, analysis.PathFlow{Dependency: idx, Operand: slot, Protection: "raw", Transforms: pathTransforms(d), Root: pathRoot(d)})
			b.request = true
		}
		b.deps = append(b.deps, d)
	}
	if slot == analysis.PathSlotFile || slot == analysis.PathSlotArchive {
		b.gaps = append(b.gaps, v.gaps...)
	}
	b.facts.Operands = append(b.facts.Operands, o)
}

// requestOrigin reports a dependency whose source is a request input field.
func requestOrigin(d analysis.Dependency) bool { return d.Source.Kind == "input_source" }

func (b *jsPathBuilder) gap(kind, detail string, n *sitter.Node) {
	b.gaps = append(b.gaps, b.f.gap(kind, detail, n))
}

// pathCall recognizes a verified Node fs read/write and records a
// path_traversal_candidate when request data reaches its path operand.
// expressSendBinding recognizes res.sendFile / res.download on a parameter of the
// enclosing function in a module that imports express.
func (f *flow) expressSendBinding(call, fn *sitter.Node) (fsBinding, bool) {
	m := f.module
	if fn.Kind() != "member_expression" {
		return fsBinding{}, false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" {
		return fsBinding{}, false
	}
	switch prop.Utf8Text(m.src) {
	case "sendFile", "download", "sendfile":
	default:
		return fsBinding{}, false
	}
	imported := ""
	for _, imp := range m.imports {
		if imp.module == "express" {
			imported = imp.module
			if imp.declaration != nil {
				break
			}
		}
	}
	if imported == "" {
		return fsBinding{}, false
	}
	if !parameterOfEnclosing(m, call, obj.Utf8Text(m.src)) {
		return fsBinding{}, false
	}
	var declaration *sitter.Node
	for _, imp := range m.imports {
		if imp.module == "express" && imp.declaration != nil {
			declaration = imp.declaration
		}
	}
	b := fsBinding{op: prop.Utf8Text(m.src), label: "res"}
	if declaration != nil {
		b.evidence = append(b.evidence, m.evidence("sink_binding", declaration))
	}
	b.evidence = append(b.evidence, m.evidence("sink_binding", fn))
	return b, true
}

// parameterOfEnclosing reports that name is a parameter of a function enclosing n.
func parameterOfEnclosing(m *sourceModule, n *sitter.Node, name string) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		params := p.ChildByFieldName("parameters")
		for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
			param := params.NamedChild(i)
			if param.Kind() == "required_parameter" || param.Kind() == "optional_parameter" {
				param = param.ChildByFieldName("pattern")
			}
			if param != nil && param.Kind() == "identifier" && param.Utf8Text(m.src) == name {
				return true
			}
		}
	}
	return false
}

func (f *flow) pathCall(call, fn, args *sitter.Node) bool {
	if f.pathRenderCall(call, fn, args) {
		return true
	}
	if f.archiveExtract(call, fn, args) {
		return true
	}
	contract := analysispacks.NodeFSContract
	binding, ok := f.nodeFSBinding(call, fn)
	spec := nodeFSOps[binding.op]
	if !ok {
		if binding, ok = f.expressSendBinding(call, fn); ok {
			contract = analysispacks.ExpressSendContract
			spec.role, spec.write = "read", false
		}
	}
	if !ok || args == nil {
		return false
	}
	var nodes []*sitter.Node
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() != "comment" {
			nodes = append(nodes, c)
		}
	}
	if len(nodes) == 0 {
		return false
	}
	b := &jsPathBuilder{f: f, facts: &analysis.PathFacts{Operation: binding.label + "." + binding.op, ContractID: contract, Platform: "posix", Role: spec.role,
		Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}}
	pathNode := nodes[0]
	if pathNode.Kind() == "spread_element" {
		b.gap("path_spread_unresolved", "spread argument to a filesystem call is not modeled", pathNode)
		if pathNode.NamedChildCount() > 0 {
			pathNode = pathNode.NamedChild(0)
		}
	}
	pathValue := f.quiet(pathNode)
	if pathValue.pathArchive == "path" {
		contract = analysispacks.UnzipperEntryContract
		b.facts.ContractID = contract
		index := 0
		if pathValue.pathArchiveBinding != nil {
			binding.evidence = append(binding.evidence, *pathValue.pathArchiveBinding)
			index = len(f.context) + len(binding.evidence) - 1
		}
		b.facts.Extractor = &analysis.PathExtractor{Library: "unzipper", Assessment: "caller_entry_path", Context: index}
	}
	b.operand(analysis.PathSlotFile, "path_operand", pathNode, pathValue)
	if !b.request {
		return true // a constant or non-request path is not a candidate
	}
	rest := nodes[1:]
	if spec.write && len(rest) > 0 {
		b.operand(analysis.PathSlotContent, "path_content", rest[0], f.quiet(rest[0]))
		rest = rest[1:]
	}
	for _, n := range rest {
		if isFunction(n) || (contract == analysispacks.ExpressSendContract && n.Kind() != "object") {
			continue
		}
		b.operand(analysis.PathSlotOption, "path_option", n, value{})
		break
	}
	context := append([]analysis.Evidence{}, f.context...)
	context = append(context, binding.evidence...)
	shift := len(context)
	context = append(context, b.context...)
	for i := range b.facts.Operands {
		for j := range b.facts.Operands[i].Context {
			b.facts.Operands[i].Context[j] += shift
		}
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), b.gaps...)
	use := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, f.module.file, call.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: "path_traversal_candidate", Sink: f.module.evidence("path_traversal_candidate", call), Dependencies: b.deps, Context: context, Gaps: gaps,
		Path: b.facts, APIModel: analysispacks.PathContract(contract), Assessment: analysis.Assessment{Status: "not_run"}}
	f.uses = append(f.uses, use)
	return true
}
