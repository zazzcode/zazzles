package parse

import (
	"fmt"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// admZipFixed is the first adm-zip release that rejects entry names escaping the
// destination (CVE-2018-1002204).
var admZipFixed = [3]int{0, 4, 11}

// declarationEvidence anchors a dependency fact to the manifest it came from.
func (s *moduleSet) declarationEvidence(pkg, version string) (analysis.Evidence, bool) {
	e, ok := s.readText("package.json")
	if !ok {
		return analysis.Evidence{}, false
	}
	e.Kind, e.Text = "dependency_declaration", fmt.Sprintf("%q resolves to %q", pkg, version)
	return e, true
}

// admZipConstructor returns the AdmZip(...) call whose result the receiver
// identifier holds, when AdmZip is a verified require/import of adm-zip.
func admZipConstructor(m *sourceModule, call *sitter.Node, receiver string) *sitter.Node {
	if parameterOfEnclosing(m, call, receiver) {
		return nil // a parameter is not the local AdmZip instance
	}
	var found *sitter.Node
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if found != nil {
			return
		}
		if n.Kind() == "variable_declarator" {
			id, v := n.ChildByFieldName("name"), n.ChildByFieldName("value")
			if id != nil && v != nil && id.Kind() == "identifier" && id.Utf8Text(m.src) == receiver && (v.Kind() == "call_expression" || v.Kind() == "new_expression") {
				callee := v.ChildByFieldName("function")
				if v.Kind() == "new_expression" {
					callee = v.ChildByFieldName("constructor")
				}
				if callee != nil && callee.Kind() == "identifier" {
					if imp, ok := m.imports[callee.Utf8Text(m.src)]; ok && imp.module == "adm-zip" && !shadowed(v, callee.Utf8Text(m.src), m.src) && !bindingReassigned(m, callee.Utf8Text(m.src)) {
						found = v
					}
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			walk(n.NamedChild(i))
		}
	}
	scope := call
	for p := call.Parent(); p != nil; p = p.Parent() {
		scope = p
		if isFunction(p) || p.Kind() == "function_declaration" {
			break
		}
	}
	walk(scope)
	return found
}

// archiveExtract recognizes zip.extractAllTo on a verified adm-zip instance and
// records a candidate when request data is the archive.
func (f *flow) archiveExtract(call, fn, args *sitter.Node) bool {
	m := f.module
	if fn.Kind() != "member_expression" || args == nil {
		return false
	}
	obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
	if obj == nil || prop == nil || obj.Kind() != "identifier" || (prop.Utf8Text(m.src) != "extractAllTo" && prop.Utf8Text(m.src) != "extractAllToAsync") {
		return false
	}
	ctor := admZipConstructor(m, call, obj.Utf8Text(m.src))
	if ctor == nil {
		return false
	}
	ctorArgs := ctor.ChildByFieldName("arguments")
	if ctorArgs == nil || ctorArgs.NamedChildCount() == 0 {
		return false
	}
	b := &jsPathBuilder{f: f, facts: &analysis.PathFacts{Operation: "adm-zip." + prop.Utf8Text(m.src), ContractID: analysispacks.AdmZipContract, Platform: "posix", Role: "write",
		Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}}
	destination := args.NamedChild(0)
	if destination == nil {
		return false
	}
	b.operand(analysis.PathSlotFile, "path_operand", destination, f.quiet(destination))
	archive := ctorArgs.NamedChild(0)
	b.operand(analysis.PathSlotArchive, "path_archive", archive, f.quiet(archive))
	if !b.request {
		return true
	}
	declared := f.set.packageVersion("adm-zip")
	assessment := "unknown_version"
	if parsed, ok := exactVersion(declared); ok {
		assessment = "fixed_version"
		if versionLess(parsed, admZipFixed) {
			assessment = "vulnerable_version"
		}
	}
	extractorContext := len(b.context)
	if declaration, ok := f.set.declarationEvidence("adm-zip", declared); ok && declared != "" {
		b.context = append(b.context, declaration)
	} else {
		b.context = append(b.context, m.evidence("dependency_declaration", ctor))
	}
	b.facts.Extractor = &analysis.PathExtractor{Library: "adm-zip", Declared: declared, Assessment: assessment}
	b.context = append(b.context, m.evidence("sink_binding", ctor))
	context := append([]analysis.Evidence{}, f.context...)
	shift := len(context)
	context = append(context, b.context...)
	b.facts.Extractor.Context = shift + extractorContext
	for i := range b.facts.Operands {
		for j := range b.facts.Operands[i].Context {
			b.facts.Operands[i].Context[j] += shift
		}
	}
	gaps := append(append([]analysis.Gap{}, f.gaps...), b.gaps...)
	f.uses = append(f.uses, analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d", f.invocation.ID, m.file, call.StartByte()), EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: "path_traversal_candidate", Sink: m.evidence("path_traversal_candidate", call), Dependencies: b.deps, Context: context, Gaps: gaps,
		Path: b.facts, APIModel: analysispacks.PathContract(analysispacks.AdmZipContract), Assessment: analysis.Assessment{Status: "not_run"}})
	return true
}
