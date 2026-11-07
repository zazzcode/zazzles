package parse

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func (s *moduleSet) resolveCall(m *sourceModule, call *sitter.Node) (*sourceModule, *sitter.Node) {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return nil, nil
	}
	name := fn.Utf8Text(m.src)
	if shadowed(call, strings.Split(name, ".")[0], m.src) {
		return nil, nil
	}
	if fn.Kind() != "identifier" {
		return s.resolve(m, name)
	}
	for p := call.Parent(); p != nil; p = p.Parent() {
		if p.Kind() != "function_declaration" {
			continue
		}
		body := p.ChildByFieldName("body")
		if body == nil {
			continue
		}
		for i := uint(0); i < body.NamedChildCount(); i++ {
			d := body.NamedChild(i)
			id := d.ChildByFieldName("name")
			if d.Kind() == "function_declaration" && id != nil && id.Utf8Text(m.src) == name {
				return m, d
			}
		}
	}
	return s.resolve(m, name)
}

func (s *moduleSet) inputHelperGaps(m *sourceModule, body *sitter.Node, req string, fields []string) []analysis.Gap {
	gaps := []analysis.Gap{}
	sinkStart := uint(0)
	sinkEnd := uint(0)
	walkCalls(body, func(call *sitter.Node) {
		fn := call.ChildByFieldName("function")
		if fn != nil && (strings.HasSuffix(fn.Utf8Text(m.src), ".query") || collectionWrite(fn.Utf8Text(m.src))) {
			if sinkStart == 0 || call.StartByte() < sinkStart {
				sinkStart = call.StartByte()
				sinkEnd = call.EndByte()
			}
		}
	})
	walkCalls(body, func(call *sitter.Node) {
		if sinkStart > 0 && (call.StartByte() > sinkStart || (call.StartByte() == sinkStart && call.EndByte() > sinkEnd)) {
			return
		}
		fn := call.ChildByFieldName("function")
		args := call.ChildByFieldName("arguments")
		if fn == nil || args == nil {
			return
		}
		name := fn.Utf8Text(m.src)
		if (name == "Number" || name == "String") && nativeStringOperation(m, call) {
			return
		}
		if strings.HasSuffix(name, ".query") || collectionWrite(name) {
			return
		}
		relevant := false
		var inspect func(*sitter.Node)
		inspect = func(n *sitter.Node) {
			if n.Kind() == "identifier" && n.Utf8Text(m.src) == req {
				relevant = true
			}
			if n.Kind() == "member_expression" {
				text := n.Utf8Text(m.src)
				for _, f := range fields {
					if text == f || text == req+".body."+f || text == req+".query."+f || text == req+".payload."+f {
						relevant = true
					}
				}
				if text == req+".body" {
					relevant = true
				}
				return
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				inspect(n.NamedChild(i))
			}
		}
		inspect(args)
		if !relevant {
			return
		}
		if nativeHashChainCall(m, call) {
			return
		}
		if len(inputPredicateEvidence(m, call)) > 0 {
			return
		}
		if _, helper := s.resolveCall(m, call); helper != nil {
			return
		}
		gaps = append(gaps, analysis.Gap{Kind: "input_helper_unresolved", Detail: "call receiving checked input lacks a definition: " + name, At: spanOf(m.file, call)})
	})
	return gaps
}
