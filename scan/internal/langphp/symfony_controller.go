package langphp

import (
	"maps"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

const symfonyResponseClass = `Symfony\Component\HttpFoundation\Response`
const symfonyAbstractController = `Symfony\Bundle\FrameworkBundle\Controller\AbstractController`

type symfonyResponseState struct {
	useID      string
	media      string
	gap        analysis.Gap
	conditions []analysis.Evidence
}

func (f *phpFlow) symfonyObjectCreation(n, clsNode *sitter.Node, class string) (phpValue, bool) {
	if f.symfony == nil || clsNode == nil {
		return phpValue{}, false
	}
	index := f.set.classIndex()
	qualified := index.qualify(f.module, class, clsNode.StartByte())
	if !strings.EqualFold(qualified, symfonyResponseClass) || len(index.byName[strings.ToLower(qualified)]) > 0 {
		return phpValue{}, false
	}
	args := phpNewArguments(n)
	values := make([]phpValue, len(args))
	for i, arg := range args {
		values[i] = f.eval(arg)
	}
	if len(values) > 0 {
		f.diagnosticOutput(n, values[0])
	}
	f.set.objects++
	response := phpValue{binding: "symfony_response", class: symfonyResponseClass, objectID: f.set.objects}
	state := symfonyResponseState{media: "html", conditions: symfonyResponseConditions(f.context)}
	if len(values) == 0 || len(values[0].deps) == 0 {
		// Track the empty response so a later setContent and header change
		// on the same object are judged together.
		f.set.responses[response.objectID] = state
		return response, true
	}
	if len(values) > 2 {
		headers := values[2]
		if headers.fields == nil {
			state.media = "unknown"
			state.gap = f.gap("render_protection_unresolved", "Response headers are not resolved", args[2])
		}
		for _, key := range sortedTwigFields(headers.fields) {
			if strings.EqualFold(key, "Content-Type") {
				state.media, state.gap = f.symfonyResponseMedia(headers.fields[key], args[2])
			}
		}
	}
	before := len(f.report.Uses)
	f.recordXSS(f.module.evidence("html_output", n), values[0], "html_text", nil)
	f.noteAuthzOutput(f.module.evidence("html_output", n), n, values[0])
	if len(f.report.Uses) > before {
		u := &f.report.Uses[before]
		u.APIModel = analysispacks.XSSContract("symfony-response-v1", "")
		state.useID = u.ID
		f.set.responses[response.objectID] = state
	}
	return response, true
}

func (f *phpFlow) symfonyResponseProperty(base phpValue, name string) (phpValue, bool) {
	if name == "headers" && base.binding == "symfony_response" {
		if _, tracked := f.set.responses[base.objectID]; tracked {
			return phpValue{binding: "symfony_response_headers", objectID: base.objectID}, true
		}
	}
	return phpValue{}, false
}

// symfonyResponseContent records Response::setContent as HTML output of the
// same response object, under the content type its headers establish.
func (f *phpFlow) symfonyResponseContent(n *sitter.Node, receiver phpValue, method string, values []phpValue) bool {
	if receiver.binding != "symfony_response" || method != "setContent" || len(values) == 0 {
		return false
	}
	f.diagnosticOutput(n, values[0])
	if len(values[0].deps) == 0 {
		return true
	}
	state, tracked := f.set.responses[receiver.objectID]
	if !tracked {
		state = symfonyResponseState{media: "html", conditions: symfonyResponseConditions(f.context)}
	}
	before := len(f.report.Uses)
	f.recordXSS(f.module.evidence("html_output", n), values[0], "html_text", nil)
	f.noteAuthzOutput(f.module.evidence("html_output", n), n, values[0])
	if len(f.report.Uses) > before {
		u := &f.report.Uses[before]
		u.APIModel = analysispacks.XSSContract("symfony-response-v1", "")
		if receiver.objectID != 0 {
			state.useID = u.ID
			f.set.responses[receiver.objectID] = state
		}
	}
	return true
}

func (f *phpFlow) symfonyResponseHeader(n *sitter.Node, receiver phpValue, method string, values []phpValue) bool {
	if receiver.binding != "symfony_response_headers" || method != "set" || len(values) < 2 {
		return false
	}
	state, exists := f.set.responses[receiver.objectID]
	if !exists {
		return false
	}
	header, known := phpSQLText(values[0])
	if known && !strings.EqualFold(header, "Content-Type") {
		return true
	}
	media, gap := f.symfonyResponseMedia(values[1], n)
	switch {
	case !known || media != state.media && !slices.Equal(symfonyResponseConditions(f.context), state.conditions):
		state.media = "unknown"
		state.gap = f.gap("render_protection_unresolved", "Response Content-Type mutation is conditional or unresolved", n)
	default:
		state.media, state.gap = media, gap
	}
	f.set.responses[receiver.objectID] = state
	return true
}

func symfonyResponseConditions(items []analysis.Evidence) []analysis.Evidence {
	var conditions []analysis.Evidence
	for _, item := range items {
		if item.Kind == "branch_precondition" || item.Kind == "branch_else_precondition" || item.Kind == "branch_false_precondition" {
			conditions = append(conditions, item)
		}
	}
	return conditions
}

func (f *phpFlow) symfonyResponseMedia(value phpValue, n *sitter.Node) (string, analysis.Gap) {
	if text, known := phpSQLText(value); known {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(text)), "text/html") {
			return "html", analysis.Gap{}
		}
		return "other", analysis.Gap{}
	}
	return "unknown", f.gap("render_protection_unresolved", "Response Content-Type is not a literal", n)
}

func (s *phpSet) finalizeSymfonyResponses(out *analysis.AnalysisReport) {
	if len(s.responses) == 0 {
		return
	}
	states := map[string]symfonyResponseState{}
	for _, id := range slices.Sorted(maps.Keys(s.responses)) {
		state := s.responses[id]
		if state.useID == "" {
			continue
		}
		if prior, exists := states[state.useID]; exists && prior.media != state.media {
			state.media = "unknown"
		}
		states[state.useID] = state
	}
	kept := out.Uses[:0]
	for _, u := range out.Uses {
		state := states[u.ID]
		if state.media == "other" {
			continue
		}
		if state.media == "unknown" {
			gap := state.gap
			if gap.Kind == "" {
				gap = analysis.Gap{Kind: "render_protection_unresolved", Detail: "Response alternatives have different content types", At: u.Sink.Span}
			}
			u.Gaps = append(u.Gaps, gap)
			u.XSS.Protection = "unknown"
			u.XSS.ProtectionReason = gap.Detail
			for i := range u.XSS.Paths {
				u.XSS.Paths[i].Protection = "unknown"
			}
		}
		kept = append(kept, u)
	}
	out.Uses = kept
}

func (f *phpFlow) symfonyControllerCall(n *sitter.Node, receiver phpValue, method string, values []phpValue) (phpValue, bool) {
	if f.symfony == nil {
		return phpValue{}, false
	}
	if f.symfonyResponseHeader(n, receiver, method, values) {
		return phpValue{}, true
	}
	if f.symfonyResponseContent(n, receiver, method, values) {
		return receiver, true
	}
	if !f.extendsSymfonyController(receiver.classDecl) {
		return phpValue{}, false
	}
	if _, override, _, _ := f.set.classIndex().method(receiver.classDecl, method); override != nil {
		return phpValue{}, false
	}
	switch method {
	case "render", "renderView", "renderBlock":
		if len(values) > 0 {
			var context phpValue
			index := 1
			if method == "renderBlock" {
				index = 2
			}
			if len(values) > index {
				context = values[index]
			}
			f.renderTwig(n, values[0], context)
		}
		return phpValue{binding: "symfony_response", class: symfonyResponseClass}, true
	case "addFlash":
		if len(values) >= 2 {
			f.twigFlashWrite(n, values[0], values[1])
		}
		return phpValue{}, true
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
				user.authz = &phpAuthz{provenance: analysis.SubjectSessionUser, class: decl.fqn}
				f.stampAuthz(user)
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
