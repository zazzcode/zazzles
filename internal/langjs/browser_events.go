package langjs

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// Event discovery is shared by exploratory flows, but callback environments and
// candidates belong only to the registration that invoked them.
type browserEvents struct {
	report    *analysis.AnalysisReport
	module    *sourceModule
	seen      map[uint]bool
	callbacks map[uint]bool
	resolved  int
	writes    map[string]bool
	calls     []*sitter.Node
}

func newBrowserEvents(report *analysis.AnalysisReport, m *sourceModule) *browserEvents {
	state := &browserEvents{report: report, module: m, seen: map[uint]bool{}, callbacks: map[uint]bool{}, writes: map[string]bool{}}
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		var left *sitter.Node
		switch n.Kind() {
		case "assignment_expression", "augmented_assignment_expression":
			left = n.ChildByFieldName("left")
		case "update_expression":
			left = n.ChildByFieldName("argument")
		}
		if left != nil {
			state.writes[left.Utf8Text(m.src)] = true
		}
		if n.Kind() == "call_expression" {
			fn := n.ChildByFieldName("function")
			if fn != nil && fn.Kind() == "member_expression" {
				prop := fn.ChildByFieldName("property")
				if prop != nil && prop.Utf8Text(m.src) == "addEventListener" {
					state.calls = append(state.calls, n)
				}
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(m.tree.RootNode())
	return state
}

func (s *browserEvents) mutated(target string, properties bool) bool {
	if s.writes[target] {
		return true
	}
	if properties {
		for text := range s.writes {
			if strings.HasPrefix(text, target+".") || strings.HasPrefix(text, target+"[") {
				return true
			}
		}
	}
	return false
}

func (f *flow) browserEvent(call, obj, args *sitter.Node, receiver value) {
	state := f.client.events
	if state == nil {
		return
	}
	if state.module != f.module {
		state.report.Gaps = append(state.report.Gaps, f.gap("browser_event_import_context_unresolved", "Imported helper registration is inventoried in its own module; caller closure binding is not modeled", call))
		return
	}
	if state.seen[call.StartByte()] {
		return
	}
	state.seen[call.StartByte()] = true
	gap := func(kind, detail string) analysis.Gap { return f.gap(kind, detail, call) }
	target := obj.Utf8Text(f.module.src)
	global := (target == "window" || target == "document") && browserGlobal(f.module, call, target)
	verified := global || receiver.domNode && !receiver.jqueryNode && state.domReceiver(f.module, obj, 0)
	if state.mutated(target, false) || state.mutated(target+".addEventListener", false) {
		verified = false
	}

	if !verified {
		state.report.Gaps = append(state.report.Gaps, gap("browser_event_receiver_unresolved", "addEventListener receiver is not a verified DOM/window binding"))
		return
	}
	event := ""
	if args != nil && args.NamedChildCount() > 0 {
		event, _ = stringLiteral(args.NamedChild(0), f.module.src)
	}
	supported := event == "click" || event == "input" || event == "change" || event == "submit" || event == "message"
	var gaps []analysis.Gap
	if !supported {
		gaps = append(gaps, gap("browser_event_name_unresolved", "Only literal click/input/change/submit/message events are modeled"))
	}
	var callback *sitter.Node
	if args != nil && args.NamedChildCount() > 1 {
		callback = state.callback(f.module, args.NamedChild(1))
	}
	if callback == nil {
		gaps = append(gaps, gap("browser_event_callback_unresolved", "Callback is not an immutable inline or local named function"))
	}
	if f.depth >= 4 || state.resolved >= 128 {
		gaps = append(gaps, gap("browser_event_limit", "Event callback depth (4) or per-file expansion (128) limit reached"))
	}
	entry := browserEntry(f.module, f.module.evidence("event_registration", call), event+" on "+target, "event")
	entry.Location = f.module.evidence("event_registration", call)
	entry.Browser.Event, entry.Browser.Target = event, target
	var handler *analysis.Evidence
	var inputs []analysis.InputBinding
	var params []boundParam
	if callback != nil && supported && len(gaps) == 0 {
		var ok bool
		params, ok = functionParameters(callback, f.module.src)
		if !ok {
			gaps = append(gaps, gap("browser_event_parameter_unresolved", "Destructured callback parameters are not modeled"))
		} else {
			e := f.module.evidence("event_callback", callback)
			handler = &e
			if len(params) > 0 {
				projection := []string{"target", "value"}
				role := "browser.event.target.value"
				if event == "message" {
					projection = []string{"data"}
					role = "browser.message.data"
				}
				inputs = []analysis.InputBinding{{Role: role, Parameter: params[0].name, Projection: projection, Origin: analysis.InputOrigin{Kind: "external", Evidence: []analysis.Evidence{f.module.evidence("event_input_binding", params[0].node)}}}}
				gaps = append(gaps, eventProjectionGaps(f.module, callback, params[0], params[0].name+"."+strings.Join(projection, "."))...)
				if state.mutated(params[0].name, true) {
					gaps = append(gaps, gap("browser_event_input_mutation", "Callback parameter mutation prevents event projection seeding"))
					inputs = nil
				}
			}
		}
	}
	ctx := parse.RegisterInvocation(state.report, entry, handler, "addEventListener", inputs, gaps)
	if handler == nil {
		return
	}
	state.resolved++
	state.callbacks[callback.StartByte()] = true
	f.runBrowserEvent(call, callback, entry, *handler, ctx, params)
}

func (f *flow) runBrowserEvent(call, callback *sitter.Node, entry analysis.EntryPoint, handler analysis.Evidence, ctx analysis.InvocationContext, params []boundParam) {
	state := f.client.events
	client := *f.client
	client.entry = entry
	child := newClientFlow(f.set, f.module, &client)
	child.invocation = ctx
	child.env = copyValues(f.env)
	keys := make([]string, 0, len(child.env))
	for key := range child.env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		v := child.env[key]
		if state.mutated(key, false) || !v.domNode && state.mutated(strings.Split(key, ".")[0], true) {
			g := f.gap("browser_event_closure_mutation", "Mutable callback closure binding: "+key, call)
			unknown := value{gaps: []analysis.Gap{g}}
			if len(v.deps) > 0 {
				unknown.deps = []analysis.Dependency{{Source: f.module.evidence("unresolved_source", call)}}
			}
			child.env[key] = unknown
			child.gaps = append(child.gaps, g)
		}
	}
	child.depth = f.depth + 1
	child.context = []analysis.Evidence{entry.Location, handler}
	for _, e := range f.context {
		if e.Kind == "render_binding" {
			child.context = append(child.context, e)
		}
	}
	for _, p := range params {
		for key := range child.env {
			if key == p.name || strings.HasPrefix(key, p.name+".") || strings.HasPrefix(key, p.name+"[") {
				delete(child.env, key)
			}
		}
		child.env[p.name] = value{}
	}
	for _, input := range ctx.Inputs {
		key := input.Parameter + "." + strings.Join(input.Projection, ".")
		// The object itself is not input text. Only the supported projection is seeded.
		child.env[key] = value{deps: []analysis.Dependency{{Source: input.Origin.Evidence[0]}}}
	}
	child.statements(callback.ChildByFieldName("body"))
	for i := range child.uses {
		u := &child.uses[i]
		for j := range u.Context {
			if u.Context[j].Kind == "control_statement" {
				u.Context[j].Kind = "conditional_test"
			}
		}
	}
	state.report.Uses = append(state.report.Uses, mergeClientUses(child.uses)...)
	for _, g := range child.gaps {
		for i := range state.report.InvocationContexts {
			if state.report.InvocationContexts[i].ID == ctx.ID {
				state.report.InvocationContexts[i].Gaps = append(state.report.InvocationContexts[i].Gaps, g)
			}
		}
	}
}

// Resolve only declarations in the callback's lexical scope. Imports, object
// methods, aliases and mutated names do not establish a callback target.
func (s *browserEvents) callback(m *sourceModule, n *sitter.Node) *sitter.Node {
	if n != nil && isFunction(n) {
		return n
	}
	if n == nil || n.Kind() != "identifier" {
		return nil
	}
	name := n.Utf8Text(m.src)
	if s.mutated(name, false) {
		return nil
	}
	fn := browserLocalValue(m, n)
	if fn != nil && (isFunction(fn) || fn.Kind() == "function_declaration") {
		return fn
	}
	return nil
}

func browserLocalValue(m *sourceModule, n *sitter.Node) *sitter.Node {
	name := n.Utf8Text(m.src)
	for scope := n.Parent(); scope != nil; scope = scope.Parent() {
		if isFunction(scope) || scope.Kind() == "function_declaration" {
			params, ok := functionParameters(scope, m.src)
			if !ok {
				return nil
			}
			for _, p := range params {
				if p.name == name {
					return nil
				}
			}
		}
		if scope.Kind() != "program" && scope.Kind() != "statement_block" {
			continue
		}
		for i := uint(0); i < scope.NamedChildCount(); i++ {
			d := scope.NamedChild(i)
			if d.Kind() == "export_statement" && d.NamedChildCount() > 0 {
				d = d.NamedChild(0)
			}
			if d.Kind() == "function_declaration" {
				id := d.ChildByFieldName("name")
				if id != nil && id.Utf8Text(m.src) == name {
					return d
				}
			}
			if d.Kind() != "lexical_declaration" && d.Kind() != "variable_declaration" {
				continue
			}
			for j := uint(0); j < d.NamedChildCount(); j++ {
				decl := d.NamedChild(j)
				id := decl.ChildByFieldName("name")
				if id != nil && id.Utf8Text(m.src) == name {
					fn := decl.ChildByFieldName("value")
					if decl.StartByte() < n.StartByte() && fn != nil {
						return fn
					}
					return nil
				}
			}
		}
	}
	return nil
}

func (s *browserEvents) unvisited(m *sourceModule) {
	for _, n := range s.calls {
		if !s.seen[n.StartByte()] {
			s.report.Gaps = append(s.report.Gaps, analysis.Gap{Kind: "browser_event_unvisited", Detail: "Registration lies outside the bounded traversed source; receiver and dispatch unresolved", At: parse.Span(m.file, n)})
		}
	}
}

func (s *browserEvents) domReceiver(m *sourceModule, n *sitter.Node, depth int) bool {
	if n == nil || depth >= 8 {
		return false
	}
	text := n.Utf8Text(m.src)
	if s.mutated(text, false) || s.mutated(text+".addEventListener", false) {
		return false
	}
	switch n.Kind() {
	case "identifier":
		if text == "window" || text == "document" {
			return browserGlobal(m, n, text)
		}
		return s.domReceiver(m, browserLocalValue(m, n), depth+1)
	case "member_expression":
		return (text == "document.body" || text == "document.documentElement") && browserGlobal(m, n, "document")
	case "call_expression":
		fn := n.ChildByFieldName("function")
		if fn == nil || s.mutated(fn.Utf8Text(m.src), false) {
			return false
		}
		switch fn.Utf8Text(m.src) {
		case "document.querySelector", "document.getElementById", "document.createElement":
			return browserGlobal(m, n, "document")
		}
	}
	return false
}

func eventProjectionGaps(m *sourceModule, callback *sitter.Node, param boundParam, supported string) []analysis.Gap {
	var gaps []analysis.Gap
	var visit func(*sitter.Node)
	visit = func(n *sitter.Node) {
		if n.Kind() == "identifier" && n.Utf8Text(m.src) == param.name && n.StartByte() != param.node.StartByte() {
			read := n
			for parent := read.Parent(); parent != nil && (parent.Kind() == "member_expression" || parent.Kind() == "subscript_expression"); parent = read.Parent() {
				if obj := parent.ChildByFieldName("object"); obj == nil || obj.StartByte() != read.StartByte() {
					break
				}
				read = parent
			}
			text := read.Utf8Text(m.src)
			if text != supported && !strings.HasPrefix(text, supported+".") && !strings.HasPrefix(text, supported+"[") && text != param.name+".origin" && text != param.name+".preventDefault" && text != param.name+".stopPropagation" {
				gaps = append(gaps, analysis.Gap{Kind: "browser_event_projection_unresolved", Detail: "Event object alias or unsupported projection: " + text, At: parse.Span(m.file, read)})
			}
		}
		for i := uint(0); i < n.NamedChildCount(); i++ {
			visit(n.NamedChild(i))
		}
	}
	visit(callback.ChildByFieldName("body"))
	return gaps
}

func (s *moduleSet) browserEventsFor(out *analysis.AnalysisReport, m *sourceModule) *browserEvents {
	if s.browserStates == nil {
		s.browserStates = map[string]*browserEvents{}
	}
	if state := s.browserStates[m.file]; state != nil {
		return state
	}
	state := newBrowserEvents(out, m)
	s.browserStates[m.file] = state
	return state
}
