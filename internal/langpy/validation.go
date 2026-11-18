package langpy

import (
	"path/filepath"
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

var pythonForm = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form\s*>`)
var pythonRequiredAttr = regexp.MustCompile(`(?i)\srequired(?:\s|=|/?>)`)
var pythonInput = regexp.MustCompile(`(?is)<input\b[^>]*>`)
var pythonHTMLAttr = regexp.MustCompile(`(?i)([a-z][a-z0-9_-]*)\s*=\s*["']([^"']*)["']`)

// formPolicies records client-declared requirements only for a form that posts to
// this handler. Browser validation is policy evidence, never server enforcement.
func (s *pythonSet) formPolicies(r pythonRoute) []analysis.Evidence {
	if r.receiver.kind != "flask" || r.receiver.templates == "" {
		return nil
	}
	var result []analysis.Evidence
	seen := map[string]bool{}
	pyWalk(r.fn.ChildByFieldName("body"), func(n *sitter.Node) {
		if n.Kind() != "call" || s.qualified(r.module, pyText(r.module, n.ChildByFieldName("function"))) != "flask.render_template" {
			return
		}
		args := pyArgs(n)
		if len(args) == 0 {
			return
		}
		name, ok := pyLiteral(r.module, args[0])
		if !ok {
			return
		}
		file, ok := s.text.Read(filepath.ToSlash(filepath.Join(r.receiver.templates, name)))
		if !ok {
			return
		}
		for _, form := range pythonForm.FindAllStringSubmatchIndex(file.Text, -1) {
			tag := file.Text[form[2]:form[3]]
			method := "GET"
			for _, a := range pythonHTMLAttr.FindAllStringSubmatch(tag, -1) {
				if strings.EqualFold(a[1], "method") {
					method = a[2]
				}
			}
			if !strings.EqualFold(method, r.route.Method) {
				continue
			}
			handler := pyText(r.module, r.fn.ChildByFieldName("name"))
			actionMatches := strings.Contains(tag, "url_for('"+handler+"')") || strings.Contains(tag, `url_for("`+handler+`")`)
			if !actionMatches {
				continue
			}
			for _, input := range pythonInput.FindAllStringIndex(file.Text[form[4]:form[5]], -1) {
				start, end := form[4]+input[0], form[4]+input[1]
				text := file.Text[start:end]
				attributes := map[string]string{}
				for _, a := range pythonHTMLAttr.FindAllStringSubmatch(text, -1) {
					attributes[strings.ToLower(a[1])] = a[2]
				}
				if attributes["name"] == "" {
					continue
				}
				policy := attributes["type"] == "email" || pythonRequiredAttr.MatchString(text)
				for _, key := range []string{"pattern", "minlength", "maxlength", "min", "max"} {
					policy = policy || attributes[key] != ""
				}
				if !policy {
					continue
				}
				e := parse.TextRange(file, start, end, "form_field_requirement")
				key := e.Span.File + ":" + text
				if !seen[key] {
					seen[key] = true
					result = append(result, e)
				}
			}
		}
	})
	return result
}

// fieldPolicy matches the actual input name, rather than borrowing a sibling's
// requirements. Browser policy is applicable only to the modeled form operand.
func (f *pythonFlow) fieldPolicy(key string) []analysis.Evidence {
	if !strings.HasPrefix(key, "form.") {
		return nil
	}
	name := strings.TrimPrefix(key, "form.")
	var result []analysis.Evidence
	for _, e := range f.context {
		if e.Kind != "form_field_requirement" {
			continue
		}
		for _, a := range pythonHTMLAttr.FindAllStringSubmatch(e.Text, -1) {
			if strings.EqualFold(a[1], "name") && a[2] == name {
				result = append(result, e)
				break
			}
		}
	}
	return result
}
func (f *pythonFlow) validationClaim(u *analysis.CandidateUse, key string, v pythonValue, policy []analysis.Evidence) {
	context := []analysis.Evidence{}
	for _, e := range u.Context {
		if e.Kind != "form_field_requirement" {
			context = append(context, e)
		}
	}
	context = append(context, policy...)
	u.Context = context
	handler := f.route.module.evidence("invoked_callable", f.route.fn)
	blockers := append([]analysis.Gap{}, f.gaps...)
	blockers = append(blockers, v.gaps...)
	blockers = append(blockers, f.guardGaps(v)...)
	constraints := []string{}
	for _, e := range policy {
		if pythonRequiredAttr.MatchString(e.Text) {
			constraints = append(constraints, "required presence: reject a missing or empty value before sensitive use; a truthiness guard followed by return on failure satisfies this requirement")
		}
		for _, a := range pythonHTMLAttr.FindAllStringSubmatch(e.Text, -1) {
			switch strings.ToLower(a[1]) {
			case "type":
				if a[2] == "email" {
					constraints = append(constraints, "email format: enforce syntactic email validity on the server, separately from required presence")
				}
			case "pattern", "minlength", "maxlength", "min", "max":
				constraints = append(constraints, strings.ToLower(a[1])+"="+a[2])
			}
		}
	}
	u.Check = &analysis.Check{ID: "source-field-policy", Method: f.route.route.Method, Path: f.route.route.PathPattern, Kind: "validation", Fields: []string{key}, Validation: "The complete policy for " + key + " in this claim is ONLY: " + strings.Join(constraints, "; ") + ". Do not demand password complexity, email syntax on a username, length/type/range restrictions, trimming or other constraints absent from this list. SQL binding, hashing and authorization are separate claims. Judge direct HTTP enforcement before sensitive use; returning a form/error before the operation enforces rejection even with HTTP status 200."}
	u.Completeness = &analysis.Completeness{ClaimKind: "validation", Required: []string{"input_source", "field_policy", "invoked_callable", "control_flow"}, Evidence: map[string][]analysis.Evidence{"input_source": {u.Sink}, "field_policy": policy, "invoked_callable": {handler}, "control_flow": append([]analysis.Evidence{handler}, context...)}, Blockers: blockers, Coverage: []analysis.Gap{}, Scope: "Bounded source-declared form policy and linked handler/helper implementation. Missing enforcement semantics remain blockers; no field-name policy inference."}
}
