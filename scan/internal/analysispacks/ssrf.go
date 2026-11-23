package analysispacks

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/guidelines"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// SSRFProtocol is the server-side request forgery question/envelope protocol.
const SSRFProtocol = "ssrf-components-v2"

// Operation-contract identifiers. Each is selected only after the parser verified
// the client binding and that a request value reaches the destination operand.
const (
	FetchURLContract          = "fetch-url-v1"
	AxiosURLContract          = "axios-url-v1"
	PythonHTTPURLContract     = "python-http-url-v1"
	NodeHTTPURLContract       = "node-http-url-v1"
	PHPURLOpenContract        = "php-url-open-v1"
	SymfonyHTTPClientContract = "symfony-http-client-v1"
	PHPShellURLClient         = "php-shell-url-client-v1"
)

var ssrfContractIDs = []string{FetchURLContract, AxiosURLContract, PythonHTTPURLContract, NodeHTTPURLContract, PHPURLOpenContract, SymfonyHTTPClientContract, PHPShellURLClient}

// SSRFContract returns a copy of the supported operation contract by verified ID.
func SSRFContract(id string) *analysis.APIModel {
	const common = " The destination operand is the claim: a request body, headers or query parameters sent to a fixed destination are data, not destination control. A relative URL resolves against a base only when the call supplies one. The response is a separate external value. Network policy, DNS answers, proxies and the deployed runtime are not inferred."
	switch id {
	case FetchURLContract:
		return &analysis.APIModel{ID: id, Library: "fetch", Reference: "https://fetch.spec.whatwg.org/#fetch-method",
			Semantics: "The global fetch(input [, init]) (WHATWG Fetch, Node.js 18 and later) requests the URL given by input; a string input is parsed as an absolute URL, so the caller chooses scheme, host, port and path. init.method, headers and body do not change the destination. By default fetch follows up to 20 redirects (init.redirect 'follow'), so a permitted first host can redirect elsewhere unless init.redirect is 'error' or 'manual'." + common}
	case AxiosURLContract:
		return &analysis.APIModel{ID: id, Library: "axios", Reference: "https://axios-http.com/docs/api_intro",
			Semantics: "axios(url [, config]), axios.get/delete/head/options(url [, config]) and axios.post/put/patch(url [, data [, config]]) request the URL given as the first argument; data and config.headers do not change the destination. config.baseURL is prepended only to a relative url; an absolute request url replaces it. In Node.js axios follows up to five redirects by default (config.maxRedirects), so a permitted first host can redirect elsewhere unless maxRedirects is 0." + common}
	case PythonHTTPURLContract:
		return &analysis.APIModel{ID: id, Library: "python-http", Reference: "https://requests.readthedocs.io/en/latest/api/#requests.request",
			Semantics: "requests.get/post/put/patch/delete/head/options(url, ...), requests.request(method, url, ...), the same httpx functions, and urllib.request.urlopen(url) request the URL given by the url argument; data, json, params and headers do not change the destination host. requests and urllib follow redirects by default (httpx does not unless follow_redirects=True), so a permitted first host can redirect elsewhere. urllib.request.urlopen also opens file: and ftp: URLs." + common}
	case PHPURLOpenContract:
		return &analysis.APIModel{ID: id, Library: "php/streams-curl", Reference: "https://www.php.net/manual/en/wrappers.php",
			Semantics: "For file_get_contents, fopen, readfile, file and the source operand of copy, argument 0 is a path or stream-wrapper URL. A local path does not choose a network destination, and an enabled URL wrapper can open a remote destination. curl_init uses argument 0 as the URL, curl_setopt with CURLOPT_URL uses argument 2, and curl_setopt_array takes the CURLOPT_URL value of argument 1. cURL URL configuration establishes the destination selection; it does not prove a later transfer executes. Wrapper registration, redirect configuration and enabled protocols need their own runtime evidence." + common}
	case SymfonyHTTPClientContract:
		return &analysis.APIModel{ID: id, Library: "symfony/http-client", Reference: "https://symfony.com/doc/6.4/http_client.html#making-requests",
			Semantics: "HttpClientInterface::request uses argument 0 for the HTTP method and argument 1 for the URL. The client can supply a base URI for a relative destination and follows redirects according to its max_redirects setting. Request options carry body and headers separately from the destination URL." + common}
	case PHPShellURLClient:
		return &analysis.APIModel{ID: id, Library: "curl", Reference: "https://curl.se/docs/manpage.html",
			Semantics: "A shell command whose program token is curl or wget requests the URL in a URL position: an argument that is not the value of a value-taking option, the value of -x or --proxy, or the value that follows --url. Quoting the argument with escapeshellarg removes shell syntax and leaves the request to the chosen host. Option values (-o, -H, -d and the rest of the option list) are not destinations. A non-literal program token is not this contract." + common}
	case NodeHTTPURLContract:
		return &analysis.APIModel{ID: id, Library: "http", Reference: "https://nodejs.org/api/http.html#httpgeturl-options-callback",
			Semantics: "Node.js http.get/request and https.get/request (including node:http / node:https) request the destination given by a URL string, a WHATWG URL object, or options.href/url/host/hostname/path/port/protocol. Forms: get/request(url[, options][, callback]) and get/request(options[, callback]). Method, headers and body/Agent options do not change the destination host by themselves. An options object spread or dynamic Agent is unresolved. Absolute URL strings choose scheme and host; relative URLs are not valid for these APIs without a host in options. Redirects are not followed by default." + common}
	}
	return nil
}

func ssrfQuestionNames() []string {
	var names []string
	for _, q := range SSRFQuestions() {
		names = append(names, q.Name)
	}
	return names
}

// SSRFQuestions returns the exact ordered SSRF claim protocol. Destination
// control, restriction and coverage are separate atomic facets.
func SSRFQuestions() []Question {
	return []Question{
		{"destination_control", "Which part of the outbound destination does request-derived text control through the verified destination operand of this call? full_url means the request value is, or supplies, the whole URL including scheme and host (for example the value passed unchanged, or concatenated before any fixed scheme and host). host means a fixed scheme with a request-derived host or authority. path_or_query means the scheme and host are fixed constants written before the request value in the same operand, so the value can change only the path, query or fragment. none means no request-derived value reaches the destination operand. unknown covers unresolved transfers, helpers or construction whose resulting URL shape the supplied source does not establish. Judge each request-derived path separately; request data sent only as body, headers or options is not destination control."},
		{"destination_restriction", "What enforced restriction, if any, limits the destination before the call on the supplied path? host_allowlist requires the parsed host (or the whole URL) of the same value to be compared with a finite set of trusted constant hosts or URLs, with a rejecting branch that terminates before the call. scheme_and_host_check requires the same value to be parsed and both its scheme and its host checked against trusted constants (or against a deny-list of internal address ranges after resolution in the supplied source) before the call, rejecting otherwise. prefix_only means a string startsWith/includes/regex test of the raw text without parsing, which userinfo, encoded or alternative host forms and redirects can pass. none means no enforced restriction: a format or presence check, a URL parse without a decision, a try/catch, an error after the request or a response content-type check is not a restriction. unknown covers unmodeled helpers whose semantics the supplied source does not establish. Redirect-following can defeat a check that is not repeated for the redirect target."},
		{"protection_coverage", "Are the relevant destination protection obligations established? complete requires every request-derived path to the destination operand and every feasible branch to be covered by the answers above, with no unknown relevant helper or reassignment after the check, and redirects either disabled or not able to leave the permitted hosts. incomplete means a supported unprotected sibling path, branch or invocation remains. unknown means coverage cannot be determined. A control on one value, branch or invocation does not cover another."},
	}
}

// SSRFChoices returns the choices of one SSRF question.
func SSRFChoices(name string) []map[string]string {
	var values [][2]string
	switch name {
	case "destination_control":
		values = [][2]string{{"full_url", "Request-derived text supplies the whole URL, including scheme and host."}, {"host", "A fixed scheme with a request-derived host or authority."}, {"path_or_query", "A fixed scheme and host precede the request value, which controls only path, query or fragment."}, {"none", "No request-derived value reaches the destination operand."}, {"unknown", "The resulting destination shape is not established by the supplied source."}}
	case "destination_restriction":
		values = [][2]string{{"host_allowlist", "The parsed host or URL of the same value must be one of a finite set of trusted constants, rejecting before the call."}, {"scheme_and_host_check", "The same value is parsed and its scheme and host are checked against trusted constants or resolved internal ranges, rejecting before the call."}, {"prefix_only", "Only an unparsed string prefix, substring or pattern test is applied."}, {"none", "No enforced restriction is established."}, {"unknown", "Control semantics are not established by the supplied source."}}
	case "protection_coverage":
		values = [][2]string{{"complete", "Relevant destination protection obligations are established."}, {"incomplete", "A relevant path, branch or sibling remains unprotected or unanalyzed."}, {"unknown", "Coverage cannot be determined from the supplied evidence."}}
	default:
		return nil
	}
	out := make([]map[string]string, 0, len(values))
	for _, v := range values {
		out = append(out, map[string]string{"value": v[0], "description": v[1]})
	}
	return out
}

var ssrfOwners = map[string]string{
	FetchURLContract:          "internal/parse/outbound_ssrf.go",
	AxiosURLContract:          "internal/parse/outbound_ssrf.go",
	PythonHTTPURLContract:     "internal/parse/python_frameworks.go",
	NodeHTTPURLContract:       "internal/parse/outbound_ssrf.go",
	PHPURLOpenContract:        "internal/langphp/php_url_open.go",
	SymfonyHTTPClientContract: "internal/langphp/php_url_open.go",
	PHPShellURLClient:         "internal/langphp/php_shell_url_client.go",
}

// ssrfDescriptors creates every SSRF component. They are separate from the
// shared query-family loops so no existing component, digest or selected request
// changes when the family is added.
func ssrfDescriptors() ([]Component, error) {
	f := FamilyForName("ssrf")
	protocols := []string{SSRFProtocol}
	base := func(id, kind, owner string, applicability []string, material string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Owner: owner, Domains: []string{"security", "outbound_request"}, Applicability: applicability, Compatibility: protocols, Tests: []string{"TestSSRFComponentSelection"}, Material: material,
			Limits: []string{"bounded static adapters only; redirects, DNS answers, proxies and network policy are never inferred; second-order destinations from storage or remote responses are observations"}}
	}
	claims := map[string][]map[string]string{}
	for _, q := range SSRFQuestions() {
		claims[q.Name] = SSRFChoices(q.Name)
	}
	pack := base(f.Pack, "pack", "internal/analysispacks", f.Kinds, "")
	pack.Dependencies = []Requirement{{f.Claim, "1"}, {f.Evidence, "1"}}
	claim := base(f.Claim, "claim_questions", "internal/analysispacks/ssrf.go", f.Kinds, claimPayload(SSRFQuestions(), claims))
	evidence := base(f.Evidence, "evidence_obligations", f.PolicyOwner, f.Kinds, "")
	evidence.Dependencies = []Requirement{{flowID(f), "1"}}
	evidence.Required = []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "destination_operand"}
	flow := base("flow.ssrf", "compiled_capability", "internal/parse/outbound_ssrf.go + internal/parse/python_frameworks.go", f.Kinds, "")
	flow.Limits = append(flow.Limits, "the destination slot only: fetch argument 0, axios URL argument, Node http/https URL or options host fields, Python url argument or keyword; an opaque axios config-object URL stays an observation")
	out := []Component{pack, claim, evidence, flow}
	for _, language := range f.Languages {
		if language == lang.TypeScript {
			continue // JavaScript and TypeScript share one document and component.
		}
		g, err := guidelines.SSRFBody(language)
		if err != nil {
			return nil, err
		}
		v := base(languageID(f, language), "language_guidance", "internal/guidelines/ssrf.go:"+g.ID, g.Languages, encoded(g))
		v.Version = g.Version
		out = append(out, v)
	}
	for _, id := range ssrfContractIDs {
		model := SSRFContract(id)
		v := base("api."+id, "api_contract", "internal/analysispacks/ssrf.go", []string{model.Library}, encoded(model))
		v.CompiledOwner = ssrfOwners[id]
		if id == PHPURLOpenContract || id == SymfonyHTTPClientContract {
			v.Compatibility = append(append([]string{}, protocols...), familyProtocol("outbound"))
		}
		v.Limits = append(v.Limits, "client version not inferred; only the verified destination operand contract applies")
		out = append(out, v)
	}
	input := nodeInputComponent()
	input.ID = "source.node-input-ssrf-v2"
	input.Applicability = []string{"ssrf_candidate"}
	input.Compatibility = protocols
	input.Tests = []string{"TestSSRFComponentSelection"}
	// Plain PHP selects its own copy of the PHP input interpretation, so the
	// shared one keeps its applicability and no earlier request changes.
	php := phpInputComponent()
	php.ID = "source.php-input-ssrf-v1"
	php.Applicability = []string{"ssrf_candidate"}
	php.Compatibility = protocols
	php.Tests = []string{"TestPHPShellURLClient", "TestArchitectureBaseline"}
	return append(out, input, php), nil
}
