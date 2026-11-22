package analysispacks

import (
	"fmt"
	"path/filepath"
	"reflect"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// Template sinks retain their actual file/span. Their compiled rendering contract
// identifies the source adapter; browser inline scripts can live in HTML files.
func sourceLanguage(u analysis.CandidateUse, f *Family) (lang.Language, bool) {
	if f.Name == "exposure" && filepath.Ext(u.Sink.Span.File) == ".twig" {
		// A diagnostic value interpolated into a template is still the PHP
		// adapter's claim: the operation that produced it is PHP source.
		return lang.PHP, u.APIModel != nil && u.APIModel.ID == PHPDiagnosticOutput
	}
	if f.Name == "authorization" && filepath.Ext(u.Sink.Span.File) == ".twig" && u.APIModel != nil && u.APIModel.ID == PHPAuthorizationOperation {
		return lang.PHP, true
	}
	if f.Name == accountFamilyName && u.APIModel != nil && u.APIModel.ID == PHPPasswordDigest {
		// A password_hashers line in security.yaml anchors a PHP claim.
		if ext := filepath.Ext(u.Sink.Span.File); ext == ".yaml" || ext == ".yml" {
			return lang.PHP, true
		}
	}
	if f.Name != "xss" {
		return lang.Detect(u.Sink.Span.File)
	}
	if u.APIModel == nil {
		return "", false
	}
	ext := filepath.Ext(u.Sink.Span.File)
	switch ext {
	case ".twig":
		return lang.PHP, u.APIModel.ID == "twig-html-output-v1"
	case ".py", ".js", ".jsx", ".ts", ".tsx", ".html", ".htm", ".ejs", ".hbs", ".handlebars", ".pug", ".vue", ".php", ".phtml":
	default:
		return "", false
	}
	switch u.APIModel.ID {
	case "python-html-output-v1":
		return lang.Python, true
	case "php-html-output-v1", "symfony-response-v1":
		return lang.PHP, true
	case "browser-output-v1", "html-output-v1":
		if l, ok := lang.Detect(u.Sink.Span.File); ok && (l == lang.JavaScript || l == lang.TypeScript) {
			return l, true
		}
		return lang.JavaScript, true
	}
	return "", false
}

func xssRoots(u analysis.CandidateUse) ([]string, error) {
	if u.XSS == nil || u.APIModel == nil {
		return nil, fmt.Errorf("XSS rendering facts and contract required")
	}
	model := XSSContract(u.APIModel.ID, u.APIModel.Library)
	if model == nil || !reflect.DeepEqual(model, u.APIModel) {
		return nil, fmt.Errorf("unsupported or conflicting XSS rendering contract")
	}
	roots := []string{"render." + model.ID, "context.xss"}
	switch u.XSS.Type {
	case "reflected":
	case "stored":
		roots = append(roots, "storage.xss")
	case "dom":
		roots = append(roots, "browser.xss")
	case "cross_tier":
		roots = append(roots, "browser.xss", "response.xss")
	default:
		return nil, fmt.Errorf("unsupported XSS claim type %q", u.XSS.Type)
	}
	if model.ID == "browser-output-v1" {
		roots = append(roots, "browser.xss")
	}
	// Protection interpretation is path-specific. Selecting it never asserts that
	// an encoder/sanitizer exists or that an unknown helper is verified.
	roots = append(roots, "protection.xss")
	return roots, nil
}

func xssDescriptors() []Component {
	makeItem := func(id, kind, owner, material string) Component {
		return Component{ID: id, Version: "1", Kind: kind, Domains: []string{"xss"}, Applicability: []string{"xss_candidate"}, Compatibility: []string{XSSProtocol}, Owner: owner, Limits: []string{"existing bounded XSS adapters only; selected interpretation never supplies missing source facts"}, Tests: []string{"TestXSSComponentSelection"}, Material: material}
	}
	items := []Component{makeItem("flow.xss", "compiled_capability", "internal/parse/xss_*.go + internal/parse/python_templates.go", "")}
	for _, id := range []string{"html-output-v1", "browser-output-v1", "python-html-output-v1", "php-html-output-v1", "symfony-response-v1", "twig-html-output-v1"} {
		items = append(items, makeItem("render."+id, "rendering_contract", "internal/analysispacks/xss.go", XSSContract(id, "").Semantics))
	}
	for _, v := range []struct{ id, owner, text string }{
		{"context.xss", "internal/parse/xss_protection.go", "Each judgment names its actual output context. HTML escaping protects only HTML text and quoted non-active attributes; not JavaScript, CSS, URL scheme safety, unquoted/active attributes or template source. Validation is not output encoding."},
		{"protection.xss", "internal/parse/xss_protection.go + internal/parse/python_templates.go", "Use only source-verified per-path encoder/sanitizer facts. Verify imports/bindings, version, options and ordering. entities/he/escape-html encode supported HTML contexts. sanitize-html and isomorphic-dompurify require the established applicable context; plain DOMPurify requires browser execution/window semantics and cannot borrow server protection. marked 0.3.5 has a documented sanitize-option bypass. SafeString/Markup disable escaping. Fake helpers, custom options, unknown versions or later unknown transforms cannot establish protection. Raw, escaped and unknown sibling writes remain independent; unknown siblings prevent all-path protection without erasing an unsafe witness."},
		{"storage.xss", "internal/parse/xss_storage*.go + internal/parse/python_templates.go", "Stored rendering needs actual storage/field and writing-origin evidence. Preserve separate write paths, caller contexts and unresolved origin blockers; matching names alone cannot establish origin."},
		{"browser.xss", "internal/parse/xss_client*.go + internal/parse/browser_events.go", "Browser-only rendering needs no invented server route. Preserve DOM/jQuery, React, Vue, Angular and inline-script binding/context facts independently. Framework identity alone cannot protect a path. Event registrations and duplicate callback invocations have distinct sources/contexts; postMessage origin conditions are not encoding or whole-application protection. Zero-use registrations remain coverage observations."},
		{"response.xss", "internal/parse/xss_cross_tier.go", "A cross-tier origin requires exactly one actual method/path producer and its requested response field. URL equality alone is insufficient. JSON alone is data, not a rendering claim. Unknown methods/origins retain gaps, never guessed producers. Browser requests are not automatically server-side SSRF."},
	} {
		items = append(items, makeItem(v.id, "xss_interpretation", v.owner, v.text))
	}
	return items
}
