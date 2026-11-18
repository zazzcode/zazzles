// Package parse turns JavaScript, TypeScript and Python source into route evidence.
//
// Routes records syntactic registrations. Analyze adds bounded handler resolution
// and local dependency evidence. Neither mode decides validation adequacy locally.
package parse

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"
	js "github.com/tree-sitter/tree-sitter-javascript/bindings/go"
	ts "github.com/tree-sitter/tree-sitter-typescript/bindings/go"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/lang"
	"github.com/zazzcode/zazzles/internal/walk"
)

// methods are Express router methods this slice understands.
var methods = map[string]string{
	"get":    "GET",
	"post":   "POST",
	"put":    "PUT",
	"patch":  "PATCH",
	"delete": "DELETE",
	"all":    "ALL",
	"use":    "USE",
}

// Routes scans root and returns a syntactic route inventory.
func Routes(root string) (*analysis.RouteInventory, error) {
	parsed, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}

	parsers, err := newParsers()
	if err != nil {
		return nil, err
	}
	defer parsers.close()

	out := &analysis.RouteInventory{
		SchemaVersion: analysis.RouteSchemaVersion,
		Root:          root,
		Routes:        []analysis.Route{},
		Gaps:          []analysis.Gap{},
	}

	for _, file := range parsed.Files {
		if file.Language != lang.JavaScript && file.Language != lang.TypeScript {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(file.Path)))
		if err != nil {
			return nil, err
		}
		parser := parsers.forPath(file.Path)
		routes, gaps, err := extractFile(parser, file.Path, src)
		if err != nil {
			return nil, err
		}
		out.Routes = append(out.Routes, routes...)
		out.Gaps = append(out.Gaps, gaps...)
	}

	var jsFiles []string
	for _, file := range parsed.Files {
		if file.Language == lang.JavaScript || file.Language == lang.TypeScript {
			jsFiles = append(jsFiles, file.Path)
		}
	}
	nextRoutes, nextGaps, err := nextRouteInventory(root, jsFiles)
	if err != nil {
		return nil, err
	}
	if len(nextRoutes) > 0 || len(nextGaps) > 0 {
		// Next.js scope excludes files the project's tsconfig removes.
		excluded := map[string]bool{}
		probe := &moduleSet{root: root, allowed: map[string]bool{}}
		probe.detectNextProjects(jsFiles)
		for _, f := range jsFiles {
			if p := probe.nextProjectFor(f); p != nil && p.nextExcluded(f) {
				excluded[f] = true
			}
		}
		kept := out.Routes[:0]
		for _, r := range out.Routes {
			if !excluded[r.Registration.File] {
				kept = append(kept, r)
			}
		}
		out.Routes = append(kept, nextRoutes...)
		keptGaps := out.Gaps[:0]
		for _, g := range out.Gaps {
			if !excluded[g.At.File] {
				keptGaps = append(keptGaps, g)
			}
		}
		out.Gaps = append(keptGaps, nextGaps...)
	}
	inv := Inventory{Root: root, Files: parsed.Files}
	py, err := openPythonSet(inv)
	if err != nil {
		return nil, err
	}
	defer py.close()
	for _, r := range py.routeEntries() {
		out.Routes = append(out.Routes, r.route)
	}
	out.Gaps = append(out.Gaps, py.gaps...)
	ph, err := openPHPSet(inv)
	if err != nil {
		return nil, err
	}
	defer ph.close()
	out.Routes = append(out.Routes, ph.phpRoutes()...)
	out.Gaps = append(out.Gaps, ph.gaps...)
	sort.Slice(out.Routes, func(i, j int) bool {
		if out.Routes[i].Registration.File != out.Routes[j].Registration.File {
			return out.Routes[i].Registration.File < out.Routes[j].Registration.File
		}
		if out.Routes[i].Registration.StartByte != out.Routes[j].Registration.StartByte {
			return out.Routes[i].Registration.StartByte < out.Routes[j].Registration.StartByte
		}
		return out.Routes[i].PathPattern < out.Routes[j].PathPattern
	})
	sort.Slice(out.Gaps, func(i, j int) bool {
		if out.Gaps[i].At.File != out.Gaps[j].At.File {
			return out.Gaps[i].At.File < out.Gaps[j].At.File
		}
		if out.Gaps[i].At.StartByte != out.Gaps[j].At.StartByte {
			return out.Gaps[i].At.StartByte < out.Gaps[j].At.StartByte
		}
		return out.Gaps[i].Kind < out.Gaps[j].Kind
	})
	return out, nil
}

type parsers struct {
	js, ts, tsx *sitter.Parser
}

func newParsers() (*parsers, error) {
	jsParser, err := openParser(js.Language())
	if err != nil {
		return nil, fmt.Errorf("javascript grammar: %w", err)
	}
	tsParser, err := openParser(ts.LanguageTypescript())
	if err != nil {
		jsParser.Close()
		return nil, fmt.Errorf("typescript grammar: %w", err)
	}
	tsxParser, err := openParser(ts.LanguageTSX())
	if err != nil {
		jsParser.Close()
		tsParser.Close()
		return nil, fmt.Errorf("tsx grammar: %w", err)
	}
	return &parsers{js: jsParser, ts: tsParser, tsx: tsxParser}, nil
}

func openParser(ptr unsafe.Pointer) (*sitter.Parser, error) {
	parser := sitter.NewParser()
	if err := parser.SetLanguage(sitter.NewLanguage(ptr)); err != nil {
		parser.Close()
		return nil, err
	}
	return parser, nil
}

func (p *parsers) close() {
	p.js.Close()
	p.ts.Close()
	p.tsx.Close()
}

func (p *parsers) forPath(path string) *sitter.Parser {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".tsx":
		return p.tsx
	case ".ts", ".mts", ".cts":
		return p.ts
	default:
		return p.js
	}
}

func extractFile(parser *sitter.Parser, file string, src []byte) ([]analysis.Route, []analysis.Gap, error) {
	tree, _ := parseRecovered(parser, src)
	if tree == nil {
		return nil, []analysis.Gap{{
			Kind:   "parse_error",
			Detail: "parser returned no tree",
			At:     analysis.Span{File: file, StartLine: 1, EndLine: 1},
		}}, nil
	}
	defer tree.Close()

	root := tree.RootNode()
	var gaps []analysis.Gap
	if root.HasError() {
		gaps = append(gaps, analysis.Gap{
			Kind:   "parse_error",
			Detail: "syntax error",
			At:     spanOf(file, root),
		})
	}

	locals := map[string]*sitter.Node{}
	collectFuncs(root, src, locals)

	var routes []analysis.Route
	walkCalls(root, func(call *sitter.Node) {
		found, dyn := routesFromCall(file, src, call, locals)
		routes = append(routes, found...)
		gaps = append(gaps, dyn...)
	})
	if routes == nil {
		routes = []analysis.Route{}
	}
	if gaps == nil {
		gaps = []analysis.Gap{}
	}
	return routes, gaps, nil
}

func walkCalls(node *sitter.Node, visit func(*sitter.Node)) {
	if node == nil {
		return
	}
	if node.Kind() == "call_expression" {
		visit(node)
	}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		walkCalls(node.NamedChild(i), visit)
	}
}

func collectFuncs(node *sitter.Node, src []byte, locals map[string]*sitter.Node) {
	if node == nil {
		return
	}
	switch node.Kind() {
	case "function_declaration":
		if name := node.ChildByFieldName("name"); name != nil && name.Kind() == "identifier" {
			locals[name.Utf8Text(src)] = node.ChildByFieldName("body")
		}
	case "variable_declarator":
		name := node.ChildByFieldName("name")
		value := node.ChildByFieldName("value")
		if name != nil && name.Kind() == "identifier" && value != nil && isFunction(value) {
			locals[name.Utf8Text(src)] = value.ChildByFieldName("body")
		}
	}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		collectFuncs(node.NamedChild(i), src, locals)
	}
}

func isFunction(node *sitter.Node) bool {
	return node.Kind() == "function_expression" || node.Kind() == "arrow_function" || node.Kind() == "function"
}

func routesFromCall(file string, src []byte, call *sitter.Node, locals map[string]*sitter.Node) ([]analysis.Route, []analysis.Gap) {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" {
		return nil, nil
	}
	prop := fn.ChildByFieldName("property")
	if prop == nil {
		return nil, nil
	}
	method, ok := methods[prop.Utf8Text(src)]
	if !ok {
		return nil, nil
	}
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return nil, nil
	}
	first := args.NamedChild(0)
	// app.use(compression()) is middleware, not a route and not a missing path.
	// app.use(prefix, router) still reports dynamic_path because prefix is a name.
	if method == "USE" && first.Kind() != "string" && first.Kind() != "array" && first.Kind() != "identifier" {
		return nil, nil
	}
	paths, dynamic, matched := pathArgs(first, src)
	// receiver.route('/path').get(handler) keeps the path on route() and the
	// handlers on the method. Any receiver works; this is not application-specific.
	handlersFrom := uint(1)
	if dynamic && method != "USE" {
		if chained, ok := chainedRoutePaths(fn, src); ok {
			paths = chained
			dynamic = false
			matched = true
			handlersFrom = 0
		}
	}
	if !matched {
		return nil, nil
	}
	// A client call such as api.post("/path", body) or app.get("setting") is not
	// a registration: a route needs a handler-shaped final argument.
	chained := false
	if obj := fn.ChildByFieldName("object"); obj != nil && obj.Kind() == "call_expression" {
		chained = true // receiver.route(path).verb(...) keeps its own handling
	}
	if method != "USE" && handlersFrom == 1 && !chained && !handlerShaped(args.NamedChild(args.NamedChildCount()-1), args.NamedChildCount()) {
		return nil, nil
	}
	at := spanOf(file, call)
	regName := fn.Utf8Text(src)
	regSpan := spanOf(file, fn)
	if handlersFrom == 0 {
		// The call node starts at the receiver, so every verb in the chain
		// would otherwise share one span. Point at the verb token instead.
		regName = "route." + prop.Utf8Text(src)
		regSpan = spanOf(file, prop)
		at.StartLine = regSpan.StartLine
		at.StartByte = regSpan.StartByte
	}
	if dynamic {
		return nil, []analysis.Gap{{
			Kind:   "dynamic_path",
			Detail: "path is not a string literal starting with /",
			At:     at,
		}}
	}

	reg := analysis.Step{
		Kind: "registration",
		Symbol: analysis.Symbol{
			Name: regName,
			Kind: "method",
			Span: regSpan,
		},
	}
	var chain []analysis.Step
	var gaps []analysis.Gap
	for i := handlersFrom; i < args.NamedChildCount(); i++ {
		steps, more := argumentSteps(file, src, args.NamedChild(i), locals)
		chain = append(chain, steps...)
		gaps = append(gaps, more...)
	}

	handler := analysis.Symbol{}
	for i := len(chain) - 1; i >= 0; i-- {
		if chain[i].Kind == "handler" {
			handler = chain[i].Symbol
			break
		}
	}

	routes := make([]analysis.Route, 0, len(paths))
	for _, path := range paths {
		steps := make([]analysis.Step, 0, 1+len(chain))
		steps = append(steps, reg)
		steps = append(steps, chain...)
		routes = append(routes, analysis.Route{
			ID:           fmt.Sprintf("route:%s:%d:%s:%s", file, at.StartByte, method, path),
			Method:       method,
			PathPattern:  path,
			Framework:    "express",
			Registration: at,
			Handler:      handler,
			Steps:        steps,
		})
	}
	return routes, gaps
}

// pathArgs classifies the first argument of a possible route call.
// matched is false when the call is not a route at all.
func pathArgs(node *sitter.Node, src []byte) (paths []string, dynamic, matched bool) {
	if node == nil {
		return nil, false, false
	}
	if text, ok := stringLiteral(node, src); ok {
		if strings.HasPrefix(text, "/") {
			return []string{text}, false, true
		}
		return nil, false, false
	}
	if node.Kind() == "array" {
		var out []string
		for i := uint(0); i < node.NamedChildCount(); i++ {
			text, ok := stringLiteral(node.NamedChild(i), src)
			if !ok || !strings.HasPrefix(text, "/") {
				return nil, true, true
			}
			out = append(out, text)
		}
		if len(out) == 0 {
			return nil, false, false
		}
		return out, false, true
	}
	return nil, true, true
}

// chainedRoutePaths finds receiver.route(path).verb(...).verb(...).
// The path belongs to the route() call. Each verb call is its own route.
func chainedRoutePaths(member *sitter.Node, src []byte) ([]string, bool) {
	obj := member.ChildByFieldName("object")
	for obj != nil && obj.Kind() == "call_expression" {
		fn := obj.ChildByFieldName("function")
		if fn == nil || fn.Kind() != "member_expression" {
			return nil, false
		}
		prop := fn.ChildByFieldName("property")
		if prop != nil && prop.Utf8Text(src) == "route" {
			args := obj.ChildByFieldName("arguments")
			if args == nil || args.NamedChildCount() == 0 {
				return nil, false
			}
			paths, dynamic, matched := pathArgs(args.NamedChild(0), src)
			if !matched || dynamic || len(paths) == 0 {
				return nil, false
			}
			return paths, true
		}
		obj = fn.ChildByFieldName("object")
	}
	return nil, false
}

func argumentSteps(file string, src []byte, node *sitter.Node, locals map[string]*sitter.Node) ([]analysis.Step, []analysis.Gap) {
	switch node.Kind() {
	case "identifier":
		return identSteps(file, src, node, locals)
	case "call_expression":
		return callSteps(file, src, node, locals, true)
	case "arrow_function", "function_expression", "function":
		step := analysis.Step{
			Kind: "handler",
			Symbol: analysis.Symbol{
				Kind: "anonymous",
				Span: spanOf(file, node),
			},
		}
		return append([]analysis.Step{step}, bodyCalls(file, src, node.ChildByFieldName("body"), "")...), nil
	default:
		return nil, nil
	}
}

func identSteps(file string, src []byte, node *sitter.Node, locals map[string]*sitter.Node) ([]analysis.Step, []analysis.Gap) {
	name := node.Utf8Text(src)
	step := analysis.Step{
		Kind: "handler",
		Symbol: analysis.Symbol{
			Name: name,
			Kind: "identifier",
			Span: spanOf(file, node),
		},
	}
	if body, ok := locals[name]; ok {
		return append([]analysis.Step{step}, bodyCalls(file, src, body, name)...), nil
	}
	return []analysis.Step{step}, []analysis.Gap{{
		Kind:   "unresolved_handler",
		Detail: name,
		At:     spanOf(file, node),
	}}
}

func callSteps(file string, src []byte, node *sitter.Node, locals map[string]*sitter.Node, unwrap bool) ([]analysis.Step, []analysis.Gap) {
	callee := node.ChildByFieldName("function")
	name := ""
	kind := "method"
	if callee != nil {
		name = callee.Utf8Text(src)
		kind = symbolKind(callee)
	}
	step := analysis.Step{
		Kind: "handler",
		Symbol: analysis.Symbol{
			Name: name,
			Kind: kind,
			Span: spanOf(file, node),
		},
	}
	steps := []analysis.Step{step}
	var gaps []analysis.Gap
	if kind == "identifier" {
		if body, ok := locals[name]; ok {
			steps = append(steps, bodyCalls(file, src, body, name)...)
		} else {
			gaps = append(gaps, analysis.Gap{
				Kind:   "unresolved_handler",
				Detail: name,
				At:     spanOf(file, node),
			})
		}
	} else if name != "" {
		gaps = append(gaps, analysis.Gap{
			Kind:   "unresolved_handler",
			Detail: name,
			At:     spanOf(file, callee),
		})
	}
	// A member call with one function argument is a wrapper plus the real handler,
	// as in wrapper(handler()) or wrapper(handler). A bare call's arguments are
	// parameters, not another step in the chain.
	if unwrap && callee != nil && callee.Kind() == "member_expression" {
		if args := node.ChildByFieldName("arguments"); args != nil && args.NamedChildCount() == 1 {
			inner := args.NamedChild(0)
			var more []analysis.Step
			var moreGaps []analysis.Gap
			switch inner.Kind() {
			case "identifier":
				more, moreGaps = identSteps(file, src, inner, locals)
			case "call_expression":
				more, moreGaps = callSteps(file, src, inner, locals, false)
			}
			steps = append(steps, more...)
			gaps = append(gaps, moreGaps...)
		}
	}
	return steps, gaps
}

func bodyCalls(file string, src []byte, body *sitter.Node, caller string) []analysis.Step {
	if body == nil {
		return nil
	}
	if body.Kind() == "call_expression" {
		callee := body.ChildByFieldName("function")
		name := ""
		if callee != nil {
			name = callee.Utf8Text(src)
		}
		return []analysis.Step{{
			Kind:   "call",
			Caller: caller,
			Symbol: analysis.Symbol{Name: name, Kind: symbolKind(callee), Span: spanOf(file, body)},
		}}
	}
	var steps []analysis.Step
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt.Kind() != "expression_statement" || stmt.NamedChildCount() == 0 {
			continue
		}
		expr := stmt.NamedChild(0)
		if expr.Kind() != "call_expression" {
			continue
		}
		callee := expr.ChildByFieldName("function")
		name := ""
		if callee != nil {
			name = callee.Utf8Text(src)
		}
		steps = append(steps, analysis.Step{
			Kind:   "call",
			Caller: caller,
			Symbol: analysis.Symbol{Name: name, Kind: symbolKind(callee), Span: spanOf(file, expr)},
		})
	}
	return steps
}

func symbolKind(callee *sitter.Node) string {
	if callee != nil && callee.Kind() == "identifier" {
		return "identifier"
	}
	return "method"
}

func stringLiteral(node *sitter.Node, src []byte) (string, bool) {
	if node == nil || node.Kind() != "string" {
		return "", false
	}
	text := node.Utf8Text(src)
	if len(text) < 2 {
		return "", false
	}
	return text[1 : len(text)-1], true
}

func spanOf(file string, node *sitter.Node) analysis.Span {
	start := node.StartPosition()
	end := node.EndPosition()
	return analysis.Span{
		File:      file,
		StartLine: int(start.Row) + 1,
		EndLine:   int(end.Row) + 1,
		StartByte: int(node.StartByte()),
		EndByte:   int(node.EndByte()),
	}
}

// handlerShaped reports a final route argument that can be a handler: a
// function, a name, a member reference or a call that may return one.
func handlerShaped(n *sitter.Node, count uint) bool {
	if n == nil || count < 2 {
		return false
	}
	switch n.Kind() {
	case "arrow_function", "function_expression", "function", "identifier", "member_expression", "call_expression", "array", "await_expression":
		return true
	}
	return false
}
