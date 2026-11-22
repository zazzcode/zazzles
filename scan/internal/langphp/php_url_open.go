package langphp

import (
	"net/url"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

const phpCurlURLField = "\x00CURLOPT_URL"

const symfonyHTTPClientInterface = `Symfony\Contracts\HttpClient\HttpClientInterface`

// symfonyURLBuiltin records only the destination operand. The boolean
// suppresses the stream's existing filesystem record when the prefix fixes
// its scheme and authority.
func (f *phpFlow) symfonyURLBuiltin(n *sitter.Node, name string, nodes []*sitter.Node, values []phpValue) bool {
	if f.symfony == nil || len(values) == 0 || !f.set.phpDeserializationBuiltin(f.module, phpCallee(n)) {
		return false
	}
	operand := 0
	switch name {
	case "file_get_contents", "fopen", "readfile", "file", "copy":
		destination := values[0]
		prefix := destination.prefix
		if len(destination.deps) == 0 {
			prefix, _ = phpSQLText(destination)
		}
		remote := phpFixedAuthority(prefix)
		if !phpLocalPathPrefix(prefix) {
			f.phpDestinationUse(n, nodes[0], name, analysispacks.PHPURLOpenContract, destination, remote)
		}
		if name == "copy" && !remote {
			f.pathUse(n, name, nodes[:1], values[:1], analysispacks.PHPFilesystemContract, "read")
		}
		return remote
	case "curl_init":
	case "curl_setopt":
		if len(values) < 3 || !phpCurlURLKey(f.module, nodes[1]) {
			return false
		}
		operand = 2
	case "curl_setopt_array":
		if len(values) >= 2 {
			if destination, ok := values[1].fields[phpCurlURLField]; ok {
				f.phpDestinationUse(n, nodes[1], name, analysispacks.PHPURLOpenContract, destination, phpFixedAuthority(destination.prefix))
			}
		}
		return false
	default:
		return false
	}
	f.phpDestinationUse(n, nodes[operand], name, analysispacks.PHPURLOpenContract, values[operand], phpFixedAuthority(values[operand].prefix))
	return false
}

func phpCurlURLKey(m *phpModule, n *sitter.Node) bool {
	return n != nil && (n.Kind() == "name" || n.Kind() == "qualified_name") &&
		strings.TrimPrefix(phpText(m, n), `\`) == "CURLOPT_URL"
}

func phpFixedAuthority(prefix string) bool {
	_, authority, ok := strings.Cut(prefix, "://")
	if !ok || strings.IndexAny(authority, "/?#") <= 0 {
		return false
	}
	target, err := url.Parse(prefix)
	return err == nil && target.Scheme != "" && target.Hostname() != ""
}

func phpLocalPathPrefix(prefix string) bool {
	return !strings.Contains(prefix, "://") &&
		(strings.HasPrefix(prefix, "/") || strings.HasPrefix(prefix, "./") || strings.HasPrefix(prefix, "../"))
}

func (f *phpFlow) symfonyOperationMethod(n *sitter.Node, receiver phpValue, method string, nodes []*sitter.Node, values []phpValue) (phpValue, bool) {
	if f.symfony == nil {
		return phpValue{}, false
	}
	if method == "file" && len(values) > 0 && f.extendsSymfonyController(receiver.classDecl) {
		f.pathUse(n, "AbstractController::file", nodes, values, analysispacks.SymfonyFileResponseContract, "read")
		return phpValue{class: symfonyBinaryFileResponseClass, binding: "symfony_response"}, true
	}
	if method != "request" || len(values) < 2 || !f.symfonyHTTPClient(receiver) {
		return phpValue{}, false
	}
	destination := values[1]
	f.phpDestinationUse(n, nodes[1], "HttpClientInterface::request", analysispacks.SymfonyHTTPClientContract, destination, phpFixedAuthority(destination.prefix))
	return phpValue{unknown: true, class: `Symfony\Contracts\HttpClient\ResponseInterface`}, true
}

func (f *phpFlow) symfonyHTTPClient(receiver phpValue) bool {
	switch strings.ToLower(receiver.class) {
	case strings.ToLower(symfonyHTTPClientInterface),
		`symfony\component\httpclient\curlhttpclient`,
		`symfony\component\httpclient\nativehttpclient`,
		`symfony\component\httpclient\scopinghttpclient`:
		return true
	}
	index := f.set.classIndex()
	for decl, depth := receiver.classDecl, 0; decl != nil && depth <= phpClassDepth; depth++ {
		interfaces := firstChildOfKind(decl.node, "class_interface_clause")
		for i := uint(0); interfaces != nil && i < interfaces.NamedChildCount(); i++ {
			name := interfaces.NamedChild(i)
			if strings.EqualFold(index.qualify(decl.module, phpText(decl.module, name), name.StartByte()), symfonyHTTPClientInterface) {
				return true
			}
		}
		decl, _ = index.parentOf(decl)
	}
	return false
}

func (f *phpFlow) phpDestinationUse(n, operand *sitter.Node, operation, contract string, destination phpValue, fixedAuthority bool) {
	var deps []phpDep
	request := false
	for _, d := range destination.deps {
		switch d.dep.Source.Kind {
		case "input_source":
			request = true
		case "storage_source", "external_response_source", "fetched_content":
		default:
			continue
		}
		d.dep.SinkSlot = analysis.OutboundSlotDestination
		deps = append(deps, d)
	}
	if len(deps) == 0 {
		return
	}
	destination.deps = deps
	kind, origin := "outbound_http_candidate", analysis.DestinationExternalData
	if request {
		kind, origin = "ssrf_candidate", analysis.DestinationRequest
	}
	u := f.addUse(kind, n, destination)
	binding := f.module.evidence("sink_binding", phpCallee(n))
	u.Context = append(u.Context, binding)
	u.APIModel = analysispacks.SSRFContract(contract)
	u.Outbound = &analysis.OutboundFacts{Operation: operation, ContractID: contract, DestinationOrigin: origin}
	evidence := f.module.evidence("destination_operand", operand)
	u.Context = append(u.Context, evidence)
	if fixedAuthority {
		prefix := f.module.evidence("destination_prefix", operand)
		prefix.Text, prefix.ModelText = destination.prefix, destination.prefix
		u.Context = append(u.Context, prefix)
	}
	if !request {
		return
	}
	for i, dep := range deps {
		path := analysis.CommandPath{Dependency: i, Operand: analysis.OutboundSlotDestination, Protection: "raw"}
		if dep.protection == "unknown" || dep.protection == phpUnwritten {
			path.Protection = "unknown"
		}
		if guard, ok := phpFilterEvidence(dep); ok {
			path.Controls = append(path.Controls, len(u.Context))
			u.Context = append(u.Context, guard)
		}
		names := parse.CommandDepNames(dep.dep)
		for j, e := range u.Context {
			switch e.Kind {
			case "branch_precondition", "branch_false_precondition":
				if m := f.set.modules[e.Span.File]; m != nil {
					test := parse.NodeAt(m.tree.RootNode(), e.Span.StartByte, e.Span.EndByte)
					if phpPresenceOnly(m, test) {
						continue
					}
				}
				if parse.MentionsAny(e.Text, names) && !parse.PresenceOnlyCondition(e.Text, names) {
					path.Controls = append(path.Controls, j)
				}
			}
		}
		if path.Protection == "raw" && len(path.Controls) > 0 {
			path.Protection = "guarded"
		}
		u.Outbound.Paths = append(u.Outbound.Paths, path)
	}
	var blockers []analysis.Gap
	for _, gap := range destination.gaps {
		switch gap.Kind {
		case "php_parameter_unresolved", "symfony_argument_unresolved", "php_value_unresolved", "php_call_unresolved", "php_loop_unresolved", "php_expression_unresolved", "work_limit", "dependency_limit", "transfer_limit":
			blockers = append(blockers, gap)
		}
	}
	u.Completeness = parse.SSRFCompleteness(u, map[string][]analysis.Evidence{
		"sink_binding":        {binding},
		"invoked_callable":    {f.entryEvidence()},
		"destination_operand": {evidence},
		"control_flow":        append([]analysis.Evidence{f.module.evidence("operation", n)}, f.context...),
	}, blockers, u.Gaps)
}
