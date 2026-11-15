package parse

import (
	"fmt"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// sensitiveMiddlewareCallees are member/identifier names that justify analyzing a
// nonfinal Express stage for any family (not only path).
var sensitiveMiddlewareCallees = map[string]bool{
	"sendFile": true, "sendfile": true, "download": true, "render": true,
	"extractAllTo": true, "extractAllToAsync": true,
	"query": true, "exec": true, "execSync": true, "execFile": true, "execFileSync": true,
	"spawn": true, "spawnSync": true,
	"send": true, "json": true, "write": true, "end": true, "redirect": true,
	"find": true, "findOne": true, "findAll": true, "findById": true, "findByPk": true,
	"info": true, "error": true, "warn": true, "debug": true, "verbose": true, "silly": true, "log": true,
	"get": true, "request": true, "post": true, "put": true, "patch": true, "delete": true,
	"createLogger": true,
}

// mayContainPathSink checks whether a middleware function or its reachable local
// callees contain a sensitive sink before running a full HTTP handler pass over
// nonfinal Express route arguments (all assessed families after E4).
func (s *moduleSet) mayContainPathSink(m *sourceModule, fn *sitter.Node) bool {
	visited := map[string]bool{}
	found := false
	var check func(*sourceModule, *sitter.Node, int)
	check = func(mod *sourceModule, node *sitter.Node, depth int) {
		if found || mod == nil || node == nil || depth > 3 {
			return
		}
		walkCalls(node, func(c *sitter.Node) {
			if found {
				return
			}
			callee := c.ChildByFieldName("function")
			if callee == nil {
				return
			}
			if _, ok := fsMember(mod, c, callee); ok {
				found = true
				return
			}
			if _, _, ok := unzipperBufferCall(mod, c); ok {
				found = true
				return
			}
			switch callee.Kind() {
			case "member_expression":
				if p := callee.ChildByFieldName("property"); p != nil && sensitiveMiddlewareCallees[p.Utf8Text(mod.src)] {
					found = true
					return
				}
			case "identifier":
				name := callee.Utf8Text(mod.src)
				if sensitiveMiddlewareCallees[name] || mod.commandNames[name].module != "" || mod.fsNames[name].module != "" {
					found = true
					return
				}
			}
			cm, next := s.resolveCall(mod, c)
			if cm == nil || next == nil {
				return
			}
			key := fmt.Sprintf("%s:%d", cm.file, next.StartByte())
			if visited[key] {
				return
			}
			visited[key] = true
			check(cm, next, depth+1)
		})
	}
	check(m, fn, 0)
	return found
}

// analyzePathChainHandlers adds sibling invocations for source-resolved nonfinal
// Express handlers across families. Existing final-handler records are left unchanged.
func (s *moduleSet) analyzePathChainHandlers(out *analysis.AnalysisReport, m, owner *sourceModule, r analysis.Route, call *sitter.Node, receiver string, context []analysis.Evidence, sourcePath, mount string, seeds registrationSeeds) {
	if r.Framework != "express" {
		return
	}
	args := call.ChildByFieldName("arguments")
	if args == nil {
		return
	}
	start := uint(1)
	if args.NamedChildCount() > 0 && isFunction(args.NamedChild(0)) {
		start = 0
	}
	for i := start; i+1 < args.NamedChildCount(); i++ {
		h := args.NamedChild(i)
		if h.Kind() == "identifier" && seeds[h.Utf8Text(m.src)] != nil {
			h = seeds[h.Utf8Text(m.src)]
		}
		hm, node := s.pathHandler(m, h)
		if hm == nil || !s.mayContainPathSink(hm, node) {
			continue
		}
		sibling := r
		sibling.ID = fmt.Sprintf("%s:path-chain:%d", r.ID, i)
		sibling.Handler = analysis.Symbol{}
		extra := &analysis.AnalysisReport{}
		s.analyzeHTTPHandler(extra, m, owner, sibling, call, receiver, context, sourcePath, mount, seeds, h, pathHandlerTarget{module: hm, node: node, index: int(i)})
		appendPathAcquisition(out, extra)
	}
}

func pathRequestParts(m *sourceModule, body *sitter.Node, parts map[string]string, gaps []analysis.Gap) (map[string]string, []analysis.Gap) {
	fn := body.Parent()
	if fn == nil {
		return parts, gaps
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil || params.NamedChildCount() == 0 {
		return parts, gaps
	}
	p := params.NamedChild(0)
	if p.Kind() == "required_parameter" || p.Kind() == "optional_parameter" {
		p = p.ChildByFieldName("pattern")
	}
	if p == nil || p.Kind() != "object_pattern" {
		return parts, gaps
	}
	if parts == nil {
		parts = map[string]string{}
	}
	found := false
	var other []string
	for i := uint(0); i < p.NamedChildCount(); i++ {
		c := p.NamedChild(i)
		name := c.Utf8Text(m.src)
		if c.Kind() == "shorthand_property_identifier_pattern" && (name == "file" || name == "files") {
			parts[name] = name
			found = true
		} else if !requestContainers[name] {
			other = append(other, name)
		}
	}
	if !found {
		return parts, gaps
	}
	var remaining []analysis.Gap
	for _, g := range gaps {
		if g.Kind != "request_projection_unresolved" && g.Kind != "request_projection_partial" {
			remaining = append(remaining, g)
		}
	}
	if len(other) > 0 {
		remaining = append(remaining, analysis.Gap{Kind: "request_projection_partial", Detail: "unmodeled request members: " + strings.Join(other, ", "), At: spanOf(m.file, p)})
	}
	return parts, remaining
}
