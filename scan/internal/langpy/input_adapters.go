package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"strings"
)

// Framework input binding is separate from shared value propagation and sink
// interpretation. Keep the legacy dependency/protection projection unchanged.
func (f *pythonFlow) source(n *sitter.Node, container, key string) pythonValue {
	e := f.module.evidence("input_source", n)
	f.recordInput(e, container, key)
	// The Python HTTP adapter establishes these implicit framework-context reads
	// at discovery, separately from the source-to-sink dependency projection.
	ambient := n.Kind() == "attribute" || n.Kind() == "subscript" || n.Kind() == "call"
	if n.Kind() == "identifier" {
		q := f.qualified(pyText(f.module, n))
		ambient = q == "flask.request" || q == "flask.session"
	}
	if ambient && f.report != nil {
		for i := range f.report.InvocationContexts {
			ctx := &f.report.InvocationContexts[i]
			if ctx.ID != f.invocation.ID {
				continue
			}
			found := false
			for _, b := range ctx.Inputs {
				found = found || (b.Role == "http.context."+container && b.Parameter == e.Text)
			}
			if !found {
				ctx.Inputs = append(ctx.Inputs, analysis.InputBinding{Role: "http.context." + container, Parameter: e.Text, Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{e}}})
			}
		}
	}
	v := pythonValue{deps: []pythonDep{{dep: analysis.Dependency{Source: e, Transfers: []analysis.Evidence{}}, protection: "raw", container: container, key: key}}}
	if key != "" && container != "session" && f.inputs != nil {
		f.inputs[container+"."+key] = v
	}
	return v
}
func (f *pythonFlow) parameters(fn *sitter.Node) {
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	for i := uint(0); i < params.NamedChildCount(); i++ {
		p := params.NamedChild(i)
		name := p
		if p.Kind() != "identifier" {
			name = p.ChildByFieldName("name")
			if name == nil {
				for j := uint(0); j < p.NamedChildCount(); j++ {
					if p.NamedChild(j).Kind() == "identifier" {
						name = p.NamedChild(j)
						break
					}
				}
			}
		}
		if name == nil {
			continue
		}
		key := pyText(f.module, name)
		if key == "self" || key == "cls" {
			if len(f.route.methods) > 0 {
				f.env[key] = pythonValue{methods: f.route.methods}
			}
			continue
		}
		if f.route.route.Framework == "fastapi" || strings.Contains(f.route.route.PathPattern, "<"+key+">") || strings.Contains(f.route.route.PathPattern, ":"+key+">") {
			container := "query"
			paramText := pyText(f.module, p)
			typ := pyText(f.module, p.ChildByFieldName("type"))
			if strings.Contains(paramText, "Body(") {
				container = "body"
			}
			// FastAPI UploadFile / File() uploads are file fields, not query scalars.
			if typ == "UploadFile" || strings.HasSuffix(typ, ".UploadFile") || strings.Contains(paramText, "File(") || f.qualified(typ) == "fastapi.UploadFile" || f.qualified(typ) == "starlette.datastructures.UploadFile" {
				container = "files"
			}
			binding := parse.HTTPInput("http."+container, key, f.module.evidence("input_binding", p))
			f.invocation.Inputs = append(f.invocation.Inputs, binding)
			v := f.source(p, parse.InputRole(binding.Role), binding.Parameter)
			if container == "files" {
				// Keep files container so .filename / .save follow uploadReceiver rules.
				for i := range v.deps {
					v.deps[i].container = "files"
					v.deps[i].key = key
				}
			}
			if f.route.route.Framework == "fastapi" && (typ == "int" || typ == "float" || typ == "bool") {
				v = pyProtect(v, "numeric")
			}
			if strings.Contains(f.route.route.PathPattern, "<int:"+key+">") {
				v = pyProtect(v, "numeric")
			}
			f.env[key] = v
		} else if i == 0 && (f.route.route.Framework == "django" || f.route.route.Framework == "pyramid" || f.route.route.Framework == "aiohttp" || f.route.route.Framework == "wsgi") {
			// The view's request argument carries the framework request object.
			f.env[key] = pythonValue{binding: "flask_request"}
		} else if i == 1 && f.route.route.Framework == "falcon" {
			f.env[key] = pythonValue{binding: "flask_request"}
		} else if i == 2 && f.route.route.Framework == "falcon" {
			f.env[key] = pythonValue{binding: "falcon_response"}
		} else {
			f.env[key] = pythonValue{}
		}
	}
}
