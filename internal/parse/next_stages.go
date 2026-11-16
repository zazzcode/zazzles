package parse

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"path"
)

// pageLayoutStages analyze ancestor layouts and templates under the page's
// invocation. They are stages, not new endpoints; controls in a layout are
// never borrowed as guards for sinks in a sibling page or component.
func (s *moduleSet) pageLayoutStages(out *analysis.AnalysisReport, m *sourceModule, p *nextProject, entry analysis.EntryPoint, invocation analysis.InvocationContext) {
	for dir := path.Dir(m.file); ; dir = path.Dir(dir) {
		for _, base := range []string{"layout", "template"} {
			for _, ext := range []string{".tsx", ".jsx", ".ts", ".js"} {
				file := joinDir(dir, base+ext)
				if !s.allowed[file] {
					continue
				}
				stage, err := s.load(file)
				if err != nil || moduleDirective(stage) == "use client" {
					continue
				}
				for _, ex := range s.nextExports(stage, 0) {
					if ex.name != "default" {
						continue
					}
					res := s.nextHandler(stage, ex.value, 0)
					if res.fn == nil {
						continue
					}
					body := res.fn.ChildByFieldName("body")
					evidence := res.module.evidence("next_"+base+"_stage", res.fn)
					for i := range out.InvocationContexts {
						if out.InvocationContexts[i].ID == invocation.ID {
							out.InvocationContexts[i].Controls = append(out.InvocationContexts[i].Controls, analysis.ApplicableControl{InvocationContextID: invocation.ID, DispatchBindingID: invocation.DispatchBindingID, Evidence: evidence})
						}
					}
					f := flow{report: out, module: res.module, set: s, entry: entry, invocation: invocation, registration: m, env: map[string]value{}, context: []analysis.Evidence{evidence, res.module.evidence("handler", body)}, helpers: &helperExpansion{budget: 24, stack: map[string]bool{}}, facts: newInputFacts(), web: &webState{project: p, framework: "nextjs", surface: "page", segments: map[string]nextSegment{}}}
					f.statements(body)
					out.Uses = append(out.Uses, f.uses...)
				}
				break
			}
		}
		if dir == p.appDir || dir == "." || dir == "" {
			break
		}
	}
}

func (s *moduleSet) pagesInitialProps(m *sourceModule, component *nextExport) *nextExport {
	if component == nil || component.value == nil {
		return nil
	}
	name := ""
	value := component.value
	if value.Kind() == "identifier" {
		name = value.Utf8Text(m.src)
	} else if id := value.ChildByFieldName("name"); id != nil {
		name = id.Utf8Text(m.src)
	}
	if name == "" {
		return nil
	}
	var found *nextExport
	root := m.tree.RootNode()
	for i := uint(0); i < root.NamedChildCount(); i++ {
		n := root.NamedChild(i)
		if n.Kind() != "expression_statement" || n.NamedChildCount() != 1 {
			continue
		}
		assign := n.NamedChild(0)
		if assign.Kind() != "assignment_expression" {
			continue
		}
		left, right := assign.ChildByFieldName("left"), assign.ChildByFieldName("right")
		if left != nil && right != nil && left.Utf8Text(m.src) == name+".getInitialProps" {
			found = &nextExport{name: "getInitialProps", decl: n, value: right, owner: m}
		}
	}
	return found
}
