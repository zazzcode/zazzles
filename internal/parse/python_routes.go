package parse

import (
	"fmt"
	"path/filepath"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type pythonReceiver struct {
	kind, prefix, templates string
	evidence                []analysis.Evidence
	uncertain               bool
}
type pythonRoute struct {
	generated     bool
	instance      string
	closures      map[string]*pythonStaticValue
	provenance    []analysis.Evidence
	route         analysis.Route
	module        *pythonModule
	fn, decorator *sitter.Node
	receiver      pythonReceiver
	html          bool
	gaps          []analysis.Gap
}

func (s *pythonSet) receiver(m *pythonModule, name string, depth int) pythonReceiver {
	if depth > 8 {
		return pythonReceiver{}
	}
	m, key := s.resolve(m, name, 0)
	if m == nil {
		return pythonReceiver{}
	}
	n := m.vars[key]
	if n == nil {
		return pythonReceiver{}
	}
	if n.Kind() == "identifier" {
		return s.receiver(m, pyText(m, n), depth+1)
	}
	if n.Kind() != "call" {
		return pythonReceiver{}
	}
	fn := pyText(m, n.ChildByFieldName("function"))
	q := s.qualified(m, fn)
	args := pyArgs(n)
	r := pythonReceiver{evidence: []analysis.Evidence{m.evidence("receiver_binding", n)}}
	switch q {
	case "flask.Flask":
		r.kind = "flask"
		r.templates = filepath.ToSlash(filepath.Join(filepath.Dir(m.file), "templates"))
		if v := pyKeywordIn(m, n, "template_folder"); v != nil {
			if text, ok := pyLiteral(m, v); ok {
				r.templates = filepath.ToSlash(filepath.Join(filepath.Dir(m.file), text))
			} else {
				r.templates = ""
				r.uncertain = true
			}
		}
	case "quart.Quart":
		r.kind = "quart"
	case "quart.Blueprint":
		r.kind = "quart"
		if v := pyKeywordIn(m, n, "url_prefix"); v != nil {
			r.prefix, _ = pyLiteral(m, v)
		}
	case "flask.Blueprint":
		r.kind = "flask"
		if v := pyKeywordIn(m, n, "url_prefix"); v != nil {
			r.prefix, _ = pyLiteral(m, v)
		}
		if v := pyKeywordIn(m, n, "template_folder"); v != nil {
			r.templates, _ = pyLiteral(m, v)
			r.templates = filepath.ToSlash(filepath.Join(filepath.Dir(m.file), r.templates))
		}
	case "fastapi.FastAPI", "fastapi.APIRouter":
		r.kind = "fastapi"
		if v := pyKeywordIn(m, n, "prefix"); v != nil {
			r.prefix, _ = pyLiteral(m, v)
		}
	case "flask_restx.Api":
		r.kind = "flask_restx"
		if len(args) > 0 {
			base := s.receiver(m, pyText(m, args[0]), depth+1)
			r.templates = base.templates
			r.evidence = append(r.evidence, base.evidence...)
		}
	default:
		if strings.HasSuffix(fn, ".namespace") {
			base := s.receiver(m, strings.TrimSuffix(fn, ".namespace"), depth+1)
			if base.kind == "flask_restx" && len(args) > 0 {
				r = base
				text, ok := pyLiteral(m, args[0])
				if !ok {
					return pythonReceiver{}
				}
				r.prefix = "/" + strings.Trim(text, "/")
				if p := pyKeywordIn(m, n, "path"); p != nil {
					r.prefix, _ = pyLiteral(m, p)
				}
				r.evidence = append(r.evidence, m.evidence("receiver_binding", n))
			}
		}
	}
	return r
}
func (s *pythonSet) routeEntries() []pythonRoute {
	var out []pythonRoute
	for _, file := range s.files {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		pyWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() == "call" {
				fn := n.ChildByFieldName("function")
				if fn != nil && fn.Kind() == "attribute" && pyText(m, fn.ChildByFieldName("attribute")) == "add_url_rule" {
					recv := s.receiver(m, pyText(m, fn.ChildByFieldName("object")), 0)
					if recv.kind == "flask" {
						s.gaps = append(s.gaps, analysis.Gap{Kind: "python_registration_unresolved", Detail: "Verified Flask add_url_rule registration is outside the supported decorator registration subset; its generated handler/path is not analyzed.", At: spanOf(m.file, n)})
					}
				}
			}
			if n.Kind() != "decorated_definition" {
				return
			}
			decl := n.ChildByFieldName("definition")
			if decl == nil {
				return
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				d := n.NamedChild(i)
				if d.Kind() != "decorator" || d.NamedChildCount() == 0 {
					continue
				}
				call := d.NamedChild(0)
				if call.Kind() != "call" {
					continue
				}
				fn := call.ChildByFieldName("function")
				if fn == nil || fn.Kind() != "attribute" {
					continue
				}
				method := pyText(m, fn.ChildByFieldName("attribute"))
				recvName := pyText(m, fn.ChildByFieldName("object"))
				recv := s.receiver(m, recvName, 0)
				if recv.kind == "" {
					continue
				}
				if method != "route" && method != "get" && method != "post" && method != "put" && method != "patch" && method != "delete" && method != "options" && method != "head" {
					continue
				}
				args := pyArgs(call)
				var pathNode *sitter.Node
				if len(args) > 0 {
					pathNode = args[0]
				} else if recv.kind == "fastapi" {
					pathNode = pyKeywordIn(m, call, "path")
				} else {
					pathNode = pyKeywordIn(m, call, "rule")
				}
				if pathNode == nil {
					s.gaps = append(s.gaps, analysis.Gap{Kind: "dynamic_path", Detail: "Python route path operand is missing or unsupported", At: spanOf(m.file, d)})
					continue
				}
				path, ok := pyLiteral(m, pathNode)
				if !ok {
					s.gaps = append(s.gaps, analysis.Gap{Kind: "dynamic_path", Detail: "Python route path is not literal", At: spanOf(m.file, d)})
					continue
				}
				prefix, mountGap := s.mountPrefix(m, recvName, recv)
				path = "/" + strings.TrimLeft(strings.TrimRight(prefix, "/")+"/"+strings.TrimLeft(path, "/"), "/")

				reg := pythonRegistration{m, n, d, call, fn, recv, recvName, path, mountGap}
				add := func(handler *sitter.Node, verb string) {
					out = append(out, s.routeFromRegistration(reg, handler, verb))
				}
				if decl.Kind() == "class_definition" && recv.kind == "flask_restx" {
					bases := decl.ChildByFieldName("superclasses")
					valid := false
					pyWalk(bases, func(c *sitter.Node) {
						if s.qualified(m, pyText(m, c)) == "flask_restx.Resource" {
							valid = true
						}
					})
					if !valid {
						continue
					}
					body := decl.ChildByFieldName("body")
					for j := uint(0); body != nil && j < body.NamedChildCount(); j++ {
						h := body.NamedChild(j)
						if h.Kind() == "decorated_definition" {
							h = h.ChildByFieldName("definition")
						}
						if h != nil && h.Kind() == "function_definition" {
							verb := strings.ToUpper(pyText(m, h.ChildByFieldName("name")))
							switch verb {
							case "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS":
								add(h, verb)
							}
						}
					}
				} else if decl.Kind() == "function_definition" {
					verbs := []string{strings.ToUpper(method)}
					if method == "route" {
						verbs = []string{"GET"}
						if v := pyKeywordIn(m, call, "methods"); v != nil {
							verbs = nil
							for j := uint(0); j < v.NamedChildCount(); j++ {
								if verb, ok := pyLiteral(m, v.NamedChild(j)); ok {
									verbs = append(verbs, strings.ToUpper(verb))
								}
							}
						}
					}
					for _, verb := range verbs {
						add(decl, verb)
					}
				}
			}
		})
	}
	return out
}
func (s *pythonSet) mountPrefix(m *pythonModule, name string, r pythonReceiver) (string, string) {
	target, key := s.resolve(m, name, 0)
	if target == nil {
		return r.prefix, ""
	}
	ctor := target.vars[key]
	if ctor == nil {
		return r.prefix, ""
	}
	q := s.qualified(target, pyText(target, pyField(ctor, "function")))
	if q != "flask.Blueprint" && q != "fastapi.APIRouter" && q != "quart.Blueprint" {
		return r.prefix, ""
	}
	count := 0
	prefix := r.prefix
	for _, file := range s.files {
		mod := s.modules[file]
		if mod == nil {
			continue
		}
		pyWalk(mod.tree.RootNode(), func(n *sitter.Node) {
			if n.Kind() != "call" {
				return
			}
			fn := pyText(mod, n.ChildByFieldName("function"))
			if !strings.HasSuffix(fn, ".register_blueprint") && !strings.HasSuffix(fn, ".include_router") {
				return
			}
			args := pyArgs(n)
			if len(args) == 0 {
				return
			}
			tm, tk := s.resolve(mod, pyText(mod, args[0]), 0)
			if tm != target || tk != key {
				return
			}
			count++
			if p := pyKeywordIn(mod, n, "url_prefix"); p != nil {
				prefix, _ = pyLiteral(mod, p)
			}
			if p := pyKeywordIn(mod, n, "prefix"); p != nil {
				v, _ := pyLiteral(mod, p)
				prefix = v + r.prefix
			}
		})
	}
	if count != 1 {
		return prefix, "Blueprint/APIRouter requires exactly one resolved static mount"
	}
	return prefix, ""
}

type pythonRegistration struct {
	module                          *pythonModule
	definition, decorator, call, fn *sitter.Node
	receiver                        pythonReceiver
	receiverName, path, mountGap    string
}

func (s *pythonSet) routeFromRegistration(reg pythonRegistration, handler *sitter.Node, verb string) pythonRoute {
	m, n, d, call, fn := reg.module, reg.definition, reg.decorator, reg.call, reg.fn
	recvName, path, mountGap, recv := reg.receiverName, reg.path, reg.mountGap, reg.receiver

	name := pyText(m, handler.ChildByFieldName("name"))
	r := analysis.Route{ID: fmt.Sprintf("route:%s:%d:%s:%s", m.file, d.StartByte(), verb, path), Method: verb, PathPattern: path, Framework: recv.kind, Registration: spanOf(m.file, d), Handler: analysis.Symbol{Name: name, Kind: "function", Span: spanOf(m.file, handler)}}
	r.Steps = []analysis.Step{{Kind: "registration", Symbol: analysis.Symbol{Name: pyText(m, fn), Kind: "decorator", Span: spanOf(m.file, d)}}, {Kind: "handler", Symbol: r.Handler}}
	pr := pythonRoute{route: r, module: m, fn: handler, decorator: call, receiver: recv, html: recv.kind == "flask"}
	if v := pyKeywordIn(m, call, "response_class"); v != nil {
		pr.html = s.qualified(m, pyText(m, v)) == "fastapi.responses.HTMLResponse"
	}
	if recv.uncertain {
		pr.gaps = append(pr.gaps, analysis.Gap{Kind: "render_configuration_unresolved", Detail: "dynamic receiver/template settings", At: r.Registration})
	}
	if mountGap != "" {
		pr.gaps = append(pr.gaps, analysis.Gap{Kind: "route_mount_unresolved", Detail: mountGap, At: r.Registration})
	}
	// Custom decorators can change arguments, enforce checks, or replace responses.
	pyWalk(n, func(other *sitter.Node) {
		if other.Kind() != "decorator" || other.Id() == d.Id() {
			return
		}
		if other.Parent().Id() != n.Id() {
			return
		}
		text := pyText(m, other)
		if strings.HasPrefix(text, "@"+recvName+".") {
			return
		}
		pr.gaps = append(pr.gaps, analysis.Gap{Kind: "python_decorator_unresolved", Detail: text, At: spanOf(m.file, other)})
	})
	return pr

}
