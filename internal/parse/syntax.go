package parse

import (
	"unsafe"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

func openParser(ptr unsafe.Pointer) (*sitter.Parser, error) {
	parser := sitter.NewParser()
	if err := parser.SetLanguage(sitter.NewLanguage(ptr)); err != nil {
		parser.Close()
		return nil, err
	}
	return parser, nil
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
