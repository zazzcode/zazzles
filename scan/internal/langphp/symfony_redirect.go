package langphp

import (
	"net/url"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

const symfonyRedirectResponseClass = `Symfony\Component\HttpFoundation\RedirectResponse`

func (f *phpFlow) symfonyRedirectCall(n *sitter.Node, receiver phpValue, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	if f.symfony == nil || !strings.EqualFold(method, "redirect") || !f.extendsSymfonyController(receiver.classDecl) {
		return phpValue{}, false
	}
	if _, override, _, _ := f.set.classIndex().method(receiver.classDecl, method); override != nil {
		return phpValue{}, false
	}
	f.symfonyRedirectUse(n, phpCallee(n), "AbstractController::redirect", nodes, values)
	return phpValue{binding: "symfony_response", class: symfonyRedirectResponseClass}, true
}

func (f *phpFlow) symfonyRedirectCreation(n, classNode *sitter.Node, class string) (phpValue, bool) {
	if f.symfony == nil || classNode == nil {
		return phpValue{}, false
	}
	index := f.set.classIndex()
	qualified := index.qualify(f.module, class, classNode.StartByte())
	if !strings.EqualFold(qualified, symfonyRedirectResponseClass) || len(index.byName[strings.ToLower(qualified)]) > 0 {
		return phpValue{}, false
	}
	nodes := phpNewArguments(n)
	values := make([]phpValue, len(nodes))
	for i, arg := range nodes {
		values[i] = f.eval(arg)
	}
	f.symfonyRedirectUse(n, classNode, "RedirectResponse::__construct", nodes, values)
	return phpValue{binding: "symfony_response", class: symfonyRedirectResponseClass}, true
}

func (f *phpFlow) symfonyRedirectUse(n, callee *sitter.Node, operation string, nodes []*sitter.Node, values []phpValue) {
	if len(values) == 0 || len(values[0].deps) == 0 || phpFixedRedirectPrefix(phpPrefixOf(values[0])) {
		return
	}
	f.recordPHPRedirect(n, callee, nodes[0], values[0], operation, analysispacks.SymfonyRedirectContract,
		"Verified Symfony redirect destination. The first argument sets the Location header.")
}

func phpFixedRedirectPrefix(prefix string) bool {
	switch {
	case strings.HasPrefix(prefix, "?"), strings.HasPrefix(prefix, "#"):
		return true
	case len(prefix) >= 2 && prefix[0] == '/' && prefix[1] != '/' && prefix[1] != '\\':
		return prefix[1] > ' '
	}
	destination, err := url.Parse(prefix)
	return err == nil && destination.Hostname() != "" && strings.HasPrefix(destination.EscapedPath(), "/")
}
