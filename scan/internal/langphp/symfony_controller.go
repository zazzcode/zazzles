package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

const symfonyResponseClass = `Symfony\Component\HttpFoundation\Response`
const symfonyAbstractController = `Symfony\Bundle\FrameworkBundle\Controller\AbstractController`

func (f *phpFlow) symfonyObjectCreation(n, clsNode *sitter.Node, class string) (phpValue, bool) {
	if f.symfony == nil || clsNode == nil {
		return phpValue{}, false
	}
	qualified := f.set.classIndex().qualify(f.module, class, clsNode.StartByte())
	if !strings.EqualFold(qualified, symfonyResponseClass) {
		return phpValue{}, false
	}
	args := phpNewArguments(n)
	values := make([]phpValue, len(args))
	for i, arg := range args {
		values[i] = f.eval(arg)
	}
	if len(values) > 0 {
		content := values[0]
		html := true
		if len(values) > 2 {
			headers := values[2]
			if headers.fields == nil {
				content.gaps = append(content.gaps, f.gap("render_protection_unresolved", "Response header type is not resolved", args[2]))
			}
			for key, value := range headers.fields {
				if !strings.EqualFold(key, "Content-Type") {
					continue
				}
				if text, known := phpSQLText(value); known {
					html = strings.HasPrefix(strings.ToLower(text), "text/html")
				} else {
					content.gaps = append(content.gaps, f.gap("render_protection_unresolved", "Response content type is not resolved", args[2]))
				}
			}
		}
		if html {
			before := len(f.report.Uses)
			f.recordXSS(f.module.evidence("html_output", n), content, "html_text", nil)
			if len(f.report.Uses) > before {
				f.report.Uses[before].APIModel = analysispacks.XSSContract("symfony-response-v1", "")
			}
		}
	}
	return phpValue{binding: "symfony_response", class: symfonyResponseClass}, true
}

func (f *phpFlow) symfonyControllerCall(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	if f.symfony == nil || !f.extendsSymfonyController(receiver.classDecl) {
		return phpValue{}, false
	}
	switch method {
	case "getParameter":
		if len(values) == 1 {
			if name, ok := phpSQLText(values[0]); ok {
				if param, ok := f.symfony.parameter(name); ok {
					if param.configuration {
						return phpValue{configuration: true, unknown: true}, true
					}
					return phpValue{constant: true, literals: []phpLiteral{{text: param.literal}}}, true
				}
			}
		}
	case "redirectToRoute", "json":
		return phpValue{binding: "symfony_response", class: symfonyResponseClass}, true
	case "createNotFoundException", "createAccessDeniedException":
		return phpValue{binding: "symfony_http_exception"}, true
	case "getUser":
		const userInterface = `Symfony\Component\Security\Core\User\UserInterface`
		if decl := f.symfonyImplementation(userInterface); decl != nil {
			if user, ok := f.symfonyEntity(decl, n); ok {
				return user, true
			}
		}
		return phpValue{unknown: true, gaps: []analysis.Gap{f.gap("symfony_argument_unresolved", "Session user class is not established", n)}}, true
	}
	return phpValue{}, false
}

func (f *phpFlow) extendsSymfonyController(decl *phpClassDecl) bool {
	index := f.set.classIndex()
	for depth := 0; decl != nil && depth <= phpClassDepth; depth++ {
		base := firstChildOfKind(decl.node, "base_clause")
		parent := firstNamedChild(base)
		if parent == nil {
			return false
		}
		if strings.EqualFold(index.qualify(decl.module, phpText(decl.module, parent), parent.StartByte()), symfonyAbstractController) {
			return true
		}
		decl, _ = index.parentOf(decl)
	}
	return false
}
