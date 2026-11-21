package langpy

import (
	sitter "github.com/tree-sitter/go-tree-sitter"
)

// pyDecodeCalls are percent-decoders (and query-string parsers, which decode): the result keeps the argument's content and
// provenance. Like str.lower or parse_qs they neither validate nor sanitize.
var pyDecodeCalls = map[string]bool{
	"urllib.parse.unquote":          true,
	"urllib.parse.unquote_plus":     true,
	"urllib.parse.unquote_to_bytes": true,
	"urllib.parse.parse_qs":         true,
	"urllib.parse.parse_qsl":        true,
}

// decodeCall models a percent-decoding call as a transfer of its argument.
// A raw (unprotected) dependency stays raw. A dependency that already carried a
// protection claim goes to "unknown": decoding can re-create characters that an
// earlier quote or escape removed, so the earlier protection is never carried across.
func (f *pythonFlow) decodeCall(n *sitter.Node) (pythonValue, bool) {
	fn := n.ChildByFieldName("function")
	if fn == nil || !pyDecodeCalls[f.qualified(pyText(f.module, fn))] {
		return pythonValue{}, false
	}
	_, _, all := f.callArguments(n)
	all.deps = append([]pythonDep{}, all.deps...)
	for i := range all.deps {
		if p := all.deps[i].protection; p != "" && p != "raw" && p != "unknown" {
			all.deps[i].protection = "unknown"
		}
	}
	// Same transfer kind as the pre-existing parse_qs model, which renderers
	// treat as content-preserving (a raw XSS operand stays raw).
	return pyTransfer(all, f.module.evidence("call_argument_dependency", n)), true
}
