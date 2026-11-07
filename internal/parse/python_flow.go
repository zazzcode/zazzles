package parse

import (
	"fmt"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type pythonDep struct {
	dep                               analysis.Dependency
	protection, container, key, entry string
}
type pythonBoundCallable struct {
	module   *pythonModule
	fn       *sitter.Node
	closure  map[string]pythonValue
	evidence []analysis.Evidence
}

type pythonValue struct {
	callable        *pythonBoundCallable
	deps            []pythonDep
	gaps            []analysis.Gap
	fields          map[string]pythonValue
	literal         string
	constant        bool
	binding, table  string
	driver          string
	templateEscape  string
	evidence        []analysis.Evidence
	built, rendered bool
	unknown         bool
	// methods resolves self.<name>() for a class-based resource handler.
	methods map[string]*pythonBoundCallable
	// thread is a threading.Thread whose target runs on start().
	thread *pythonThread
}
type pythonThread struct {
	callable *pythonBoundCallable
	args     []pythonValue
	node     *sitter.Node
}
type pythonWrite struct {
	value    pythonValue
	entry    string
	evidence analysis.Evidence
}
type pythonFlow struct {
	set        *pythonSet
	module     *pythonModule
	route      pythonRoute
	invocation analysis.InvocationContext
	report     *analysis.AnalysisReport
	env        map[string]pythonValue
	context    []analysis.Evidence
	gaps       []analysis.Gap
	depth      int
	work       *int
	stack      map[string]bool
	returns    pythonValue
	imports    map[string]pythonImport
	inputs     map[string]pythonValue
	guards     map[string][]analysis.Gap
}

func pyBody(n *sitter.Node) *sitter.Node {
	if b := pyField(n, "body"); b != nil {
		return b
	}
	if n != nil {
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "block" {
				return c
			}
		}
	}
	return nil
}
func (f *pythonFlow) gap(kind, detail string, n *sitter.Node) analysis.Gap {
	return analysis.Gap{Kind: kind, Detail: detail, At: spanOf(f.module.file, n)}
}
func (f *pythonFlow) source(n *sitter.Node, container, key string) pythonValue {
	e := f.module.evidence("input_source", n)
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
func (s *pythonSet) analyze(out *analysis.AnalysisReport, r pythonRoute) {
	m := r.module
	handler := m.evidence("invoked_callable", r.fn)
	registration := m.evidence("entry_registration", r.decorator)
	registration.Span = r.route.Registration
	registration.Text = string(m.src[registration.Span.StartByte:registration.Span.EndByte])
	registration.ModelText = modelSource(m.src, uint(registration.Span.StartByte), uint(registration.Span.EndByte), m.comments)
	instance := r.instance
	if instance == "" {
		instance = m.file + ":" + m.hash + ":" + r.route.Framework
	}
	entry := httpEntry(r.route, registration, instance)
	entry.Gaps = append([]analysis.Gap{}, r.gaps...)
	mechanism := "decorator_registration"
	if r.generated {
		mechanism = "factory_expansion"
	}
	invocation := registerInvocation(out, entry, &handler, mechanism, nil, r.gaps)
	if r.generated {
		out.Registrations[len(out.Registrations)-1].DerivedFrom = r.provenance
	}
	work := 0
	f := &pythonFlow{set: s, module: m, route: r, invocation: invocation, report: out, env: map[string]pythonValue{}, context: append([]analysis.Evidence{handler, m.evidence("route_registration", r.decorator)}, r.receiver.evidence...), gaps: append([]analysis.Gap{}, r.gaps...), work: &work, stack: map[string]bool{}}
	f.guards = map[string][]analysis.Gap{}
	f.inputs = map[string]pythonValue{}
	f.imports = map[string]pythonImport{}
	f.context = append(f.context, s.formPolicies(r)...)
	keys := []string{}
	for k := range r.closures {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := r.closures[k]
		f.env[k] = pythonValue{literal: v.text, constant: true, evidence: v.evidence}
		f.invocation.Closures = append(f.invocation.Closures, analysis.InputBinding{Constant: &v.text, Role: "closure", Parameter: k, Origin: analysis.InputOrigin{Kind: "constant", Evidence: v.evidence}})
	}
	f.context = append(f.context, r.provenance...)
	f.parameters(r.fn)
	out.InvocationContexts[len(out.InvocationContexts)-1] = f.invocation
	f.block(r.fn.ChildByFieldName("body"))
	f.finishValidation()
	for i := range out.Entries {
		if out.Entries[i].ID == entry.ID {
			out.Entries[i].Gaps = pythonMergeGaps(out.Entries[i].Gaps, f.gaps)
		}
	}
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
			if strings.Contains(pyText(f.module, p), "Body(") {
				container = "body"
			}
			binding := httpInput("http."+container, key, f.module.evidence("input_binding", p))
			f.invocation.Inputs = append(f.invocation.Inputs, binding)
			v := f.source(p, inputRole(binding.Role), binding.Parameter)
			typ := pyText(f.module, p.ChildByFieldName("type"))
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
func (f *pythonFlow) clone() *pythonFlow {
	c := *f
	c.env = map[string]pythonValue{}
	for k, v := range f.env {
		c.env[k] = v
	}
	c.gaps = append([]analysis.Gap{}, f.gaps...)
	c.context = append([]analysis.Evidence{}, f.context...)
	c.guards = map[string][]analysis.Gap{}
	for k, v := range f.guards {
		c.guards[k] = append([]analysis.Gap{}, v...)
	}
	c.returns = pythonValue{}
	c.imports = map[string]pythonImport{}
	for k, v := range f.imports {
		c.imports[k] = v
	}
	return &c
}
func (f *pythonFlow) merge(branches ...*pythonFlow) {
	keys := map[string]bool{}
	for _, b := range branches {
		f.mergeGuards(b)
		f.gaps = pythonMergeGaps(f.gaps, b.gaps)
		f.returns = pyJoin(f.returns, b.returns, 0)
		for k := range b.env {
			keys[k] = true
		}
	}
	for key := range keys {
		var v pythonValue
		for _, b := range branches {
			if value, ok := b.env[key]; ok {
				v = pyJoin(v, value, 0)
			} else {
				v = pyJoin(v, pythonValue{unknown: true}, 0)
			}
		}
		f.env[key] = v
	}
}

// block returns true when the modeled path cannot fall through.
func (f *pythonFlow) addUse(kind string, n *sitter.Node, v pythonValue) *analysis.CandidateUse {
	v.gaps = append(v.gaps, f.guardGaps(v)...)
	deps := []analysis.Dependency{}
	for _, d := range v.deps {
		deps = append(deps, d.dep)
	}
	u := analysis.CandidateUse{ID: fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, f.module.file, n.StartByte(), kind), EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: kind, Sink: f.module.evidence(kind, n), Dependencies: deps, Context: append([]analysis.Evidence{}, f.context...), Gaps: append(append([]analysis.Gap{}, f.gaps...), v.gaps...), Assessment: analysis.Assessment{Status: "not_run"}}
	f.report.Uses = append(f.report.Uses, u)
	return &f.report.Uses[len(f.report.Uses)-1]
}

func (f *pythonFlow) finishValidation() {
	sunk := map[string]bool{}
	for _, u := range f.report.Uses {
		if u.EntryID != f.invocation.EntryID || u.Kind != "sql_query_candidate" {
			continue
		}
		for _, d := range u.Dependencies {
			for key, v := range f.inputs {
				for _, input := range v.deps {
					if input.dep.Source.Span == d.Source.Span {
						sunk[key] = true
					}
				}
			}
		}
	}
	keys := []string{}
	for key := range f.inputs {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		policy := f.fieldPolicy(key)
		if sunk[key] && len(policy) == 0 {
			continue
		}
		v := f.inputs[key]
		if len(v.deps) == 0 {
			continue
		}
		sink := v.deps[0].dep.Source
		u := analysis.CandidateUse{ID: "input:" + f.invocation.ID + ":" + key, EntryID: f.invocation.EntryID, InvocationContextID: f.invocation.ID, Kind: "input_validation_candidate", Sink: sink, Context: append([]analysis.Evidence{}, f.context...), Gaps: append([]analysis.Gap{}, f.gaps...), Assessment: analysis.Assessment{Status: "not_run"}, Dependencies: []analysis.Dependency{v.deps[0].dep}}
		if len(policy) > 0 {
			f.validationClaim(&u, key, v, policy)
		} else {
			u.Gaps = append(u.Gaps, analysis.Gap{Kind: "input_validation_unresolved", Detail: key + ": assess actual enforcing conditions in handler; no external business policy was supplied", At: sink.Span})
		}
		f.report.Uses = append(f.report.Uses, u)
	}
}
