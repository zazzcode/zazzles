package langphp

import (
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

const symfonyProcessClass = `Symfony\Component\Process\Process`
const symfonyBinaryFileResponseClass = `Symfony\Component\HttpFoundation\BinaryFileResponse`

func (f *phpFlow) symfonyProcessStatic(n *sitter.Node, class string, scope *sitter.Node, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	if f.symfony == nil || scope == nil || method != "fromShellCommandline" ||
		!strings.EqualFold(f.set.classIndex().qualify(f.module, class, scope.StartByte()), symfonyProcessClass) {
		return phpValue{}, false
	}
	return f.phpProcessUse(n, "Process::fromShellCommandline", analysispacks.SymfonyProcessContract, "enabled", "none",
		[]string{analysis.CommandSlotShell}, values, nodes), true
}

func (f *phpFlow) symfonyOperationObject(n, classNode *sitter.Node, class string) (phpValue, bool) {
	if f.symfony == nil || classNode == nil {
		return phpValue{}, false
	}
	qualified := f.set.classIndex().qualify(f.module, class, classNode.StartByte())
	switch {
	case strings.EqualFold(qualified, symfonyProcessClass):
		nodes := phpNewArguments(n)
		if len(nodes) == 0 {
			return phpValue{class: qualified, unknown: true}, true
		}
		f.symfonyProcessArgv(n, nodes[0])
		for _, option := range nodes[1:] {
			f.eval(option)
		}
		return phpValue{class: qualified, unknown: true}, true
	case strings.EqualFold(qualified, symfonyBinaryFileResponseClass):
		nodes := phpNewArguments(n)
		values := make([]phpValue, len(nodes))
		for i, arg := range nodes {
			values[i] = f.eval(arg)
		}
		f.pathUse(n, "BinaryFileResponse::__construct", nodes, values, analysispacks.SymfonyFileResponseContract, "read")
		return phpValue{class: qualified, binding: "symfony_response"}, true
	default:
		return phpValue{}, false
	}
}

func (f *phpFlow) symfonyProcessArgv(call, argv *sitter.Node) {
	unknown := func(value phpValue) {
		value.gaps = append(value.gaps, f.gap("php_value_unresolved", "Symfony Process argv shape is not established", argv))
		f.phpProcessUse(call, "Process::__construct", analysispacks.SymfonyProcessContract, "disabled", "unknown",
			[]string{analysis.CommandSlotArgvUnknown}, []phpValue{value}, []*sitter.Node{argv})
	}
	if argv.Kind() != "array_creation_expression" {
		unknown(f.eval(argv))
		return
	}
	var nodes []*sitter.Node
	for i := uint(0); i < argv.NamedChildCount(); i++ {
		element := argv.NamedChild(i)
		if element.Kind() == "comment" {
			continue
		}
		if element.Kind() != "array_element_initializer" || element.NamedChildCount() != 1 || element.NamedChild(0).Kind() == "variadic_unpacking" {
			unknown(f.eval(argv))
			return
		}
		nodes = append(nodes, element.NamedChild(0))
	}
	values := make([]phpValue, len(nodes))
	slots := make([]string, len(nodes))
	for i, node := range nodes {
		values[i] = f.eval(node)
		slots[i] = analysis.CommandSlotArgumentPrefix + strconv.Itoa(i)
	}
	if len(slots) > 0 {
		slots[0] = analysis.CommandSlotExecutable
	}
	f.phpProcessUse(call, "Process::__construct", analysispacks.SymfonyProcessContract, "disabled", "literal_list",
		slots, values, nodes)
}
