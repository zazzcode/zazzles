package guidelines

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// sectionEdit rewrites one selected section. Optional phrase edits preserve the
// accepted SQL bytes; required edits fail the projection when their phrase is
// absent so a canonical-document change cannot silently drop family guidance.
type sectionEdit struct {
	old, from, to, replacement string
	required                   bool
}

func replace(old, replacement string) sectionEdit {
	return sectionEdit{old: old, replacement: replacement}
}

func mustReplace(old, replacement string) sectionEdit {
	return sectionEdit{old: old, replacement: replacement, required: true}
}

func mustRemove(phrase string) sectionEdit {
	return sectionEdit{old: phrase, required: true}
}

// cutSpan removes the text between two literal anchors, keeping the end anchor.
func cutSpan(from, to string) sectionEdit {
	return sectionEdit{from: from, to: to, required: true}
}

type sectionSpec struct {
	title string
	edits []sectionEdit
}

// projectionSpec declares one family's required sections in selection order.
// Every listed title must exist exactly once in the canonical document.
type projectionSpec struct {
	// marker keeps a preamble line that contains it (TypeScript note).
	marker   string
	sections []sectionSpec
}

func applyEdits(body string, edits []sectionEdit) (string, error) {
	for _, e := range edits {
		switch {
		case e.old != "":
			if !strings.Contains(body, e.old) && e.required {
				return "", fmt.Errorf("required guidance phrase missing: %q", e.old)
			}
			body = strings.ReplaceAll(body, e.old, e.replacement)
		default:
			start, end := strings.Index(body, e.from), strings.Index(body, e.to)
			if start < 0 || end <= start {
				return "", fmt.Errorf("required guidance span %q..%q missing", e.from, e.to)
			}
			body = body[:start] + body[end:]
		}
	}
	return body, nil
}

// project selects the required sections of one canonical language document.
// A missing, renamed or duplicated required section is an error, never a
// silently smaller projection.
func project(raw string, spec projectionSpec) (string, error) {
	sections := strings.Split(raw, "\n## ")
	var selected []string
	for _, line := range strings.Split(sections[0], "\n") {
		if strings.HasPrefix(line, "id:") || strings.HasPrefix(line, "version:") || strings.HasPrefix(line, "languages:") || (spec.marker != "" && strings.Contains(line, spec.marker)) {
			selected = append(selected, line)
		}
	}
	titles := map[string]string{}
	counts := map[string]int{}
	for _, section := range sections[1:] {
		title, _, _ := strings.Cut(section, "\n")
		counts[title]++
		titles[title] = section
	}
	for _, want := range spec.sections {
		if counts[want.title] != 1 {
			return "", fmt.Errorf("required guidance section %q appears %d times", want.title, counts[want.title])
		}
		body, err := applyEdits(titles[want.title], want.edits)
		if err != nil {
			return "", fmt.Errorf("%s: %w", want.title, err)
		}
		selected = append(selected, "\n## "+strings.TrimSpace(body))
	}
	return strings.Join(selected, "\n"), nil
}

// sqlSpec reproduces the accepted SQL projection byte-for-byte; its output is
// frozen by test against the accepted SQL component tree.
func sqlSpec(language lang.Language) projectionSpec {
	trim := []sectionEdit{
		replace(" or a `$where` string", ""),
		replace("SQL or NoSQL", "SQL"),
		replace("`Array.find` is not a NoSQL query.", ""),
	}
	spec := projectionSpec{marker: "TypeScript types are not runtime validation", sections: []sectionSpec{
		{"Posture", trim}, {"Validation", trim}, {"Free text", trim}, {"Sinks", trim}, {"Do not claim", trim},
		{"Evidence and human-readable results", []sectionEdit{
			replace("SQL and NoSQL", "SQL"),
			cutSpan("A NoSQL document accepting", "A numeric conversion"),
			replace("Use NoSQL as one word. ", ""),
		}},
	}}
	if language == lang.Python {
		// The Python document has no evidence-section heading; the JavaScript
		// TypeScript marker also does not apply.
		spec.marker = ""
		spec.sections = spec.sections[:5]
	}
	return spec
}

// noSQLSpec keeps selector/operator and executable-expression interpretation;
// it drops SQL-only and unrelated logging guidance.
func noSQLSpec() projectionSpec {
	return projectionSpec{marker: "TypeScript types are not runtime validation", sections: []sectionSpec{
		{"Posture", nil},
		{"Validation", nil},
		{"Free text", nil},
		{"Sinks", []sectionEdit{mustRemove("Logging a SQL-looking string is not a query. ")}},
		{"Do not claim", nil},
		{"Evidence and human-readable results", []sectionEdit{cutSpan("An ORM search value", "A NoSQL document")}},
	}}
}

// validationSpec keeps field-policy interpretation only; sink construction and
// query-protection guidance belong to the query families.
func validationSpec() projectionSpec {
	return projectionSpec{marker: "TypeScript types are not runtime validation", sections: []sectionSpec{
		{"Posture", nil},
		{"Validation", nil},
		{"Free text", nil},
		{"Do not claim", nil},
		{"Evidence and human-readable results", []sectionEdit{
			cutSpan("A query-pattern match", "A numeric conversion"),
			mustRemove("Use NoSQL as one word. "),
		}},
	}}
}

func validationPythonSpec() projectionSpec {
	return projectionSpec{sections: []sectionSpec{
		{"Posture", nil},
		{"Validation", nil},
		{"Free text", nil},
		{"Do not claim", nil},
	}}
}

// phpSQLSpec projects the PHP document's shared query-family sections.
func phpSQLSpec() projectionSpec {
	return projectionSpec{sections: []sectionSpec{
		{"Posture", nil},
		{"Validation", nil},
		{"Free text", nil},
		{"Sinks", nil},
		{"Do not claim", nil},
	}}
}

//go:embed logging_php.md
var phpLoggingGuidelines string

// FamilyBody returns the validated section projection of the canonical
// language document for one claim family. Unmigrated families keep the full
// document through Body.
func FamilyBody(language lang.Language, family string) (AnalysisGuidelines, error) {
	if language == lang.PHP && family == "logging" {
		return parse(phpLoggingGuidelines)
	}
	item, ok := ForLanguage(language)
	if !ok || language == lang.Go {
		return AnalysisGuidelines{}, fmt.Errorf("no analysis guidelines for %s", language)
	}
	var spec projectionSpec
	switch family {
	case "logging":
		spec = projectionSpec{sections: []sectionSpec{{"Logging", nil}, {"Do not claim", nil}}}
	case "xss":
		title := "Cross-site scripting"
		if language == lang.Python || language == lang.PHP {
			title = "Rendering"
		}
		spec = projectionSpec{sections: []sectionSpec{{title, []sectionEdit{replace("xss-use-v1", "xss-components-v2")}}, {"Do not claim", nil}}}
	case "sql":
		if language == lang.PHP {
			spec = phpSQLSpec()
		} else {
			spec = sqlSpec(language)
		}
	case "nosql":
		if language != lang.JavaScript && language != lang.TypeScript {
			return AnalysisGuidelines{}, fmt.Errorf("nosql guidance requires the JavaScript document, not %s", language)
		}
		spec = noSQLSpec()
	case "validation":
		if language == lang.Python || language == lang.PHP {
			spec = validationPythonSpec()
		} else {
			spec = validationSpec()
		}
	default:
		return AnalysisGuidelines{}, fmt.Errorf("unknown guidance family %q", family)
	}
	body, err := project(item.Body, spec)
	if err != nil {
		return AnalysisGuidelines{}, err
	}
	item.Body = body
	return item, nil
}
