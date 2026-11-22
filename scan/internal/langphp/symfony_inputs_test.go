package langphp

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSymfonyInputs(t *testing.T) {
	inputs, err := Analyze(filepath.Join("testdata", "symfony", "inputs"), "")
	if err != nil {
		t.Fatal(err)
	}
	services, err := Analyze(filepath.Join("testdata", "symfony", "services"), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, entry, file       string
		line                  int
		origins, fields       []string
		storage, control, gap string
	}{
		{"IN-01", "ANY /query", "src/Controller/Inputs.php", 16, []string{"http.query"}, []string{"q"}, "", "", ""},
		{"IN-02", "ANY /form", "src/Controller/Inputs.php", 21, []string{"http.form"}, []string{"b"}, "", "", ""},
		{"IN-03", "ANY /any", "src/Controller/Inputs.php", 26, []string{"http.path_query_or_form"}, []string{"a"}, "", "", ""},
		{"IN-04", "ANY /headers", "src/Controller/Inputs.php", 31, []string{"http.headers", "http.cookies"}, []string{"X-Tag", "c"}, "", "", ""},
		{"IN-05", "ANY /item/{id}", "src/Controller/Inputs.php", 36, []string{"http.path"}, []string{"id"}, "", "", ""},
		{"IN-06", "ANY /mapped", "src/Controller/Inputs.php", 41, []string{"http.query"}, []string{"q"}, "", "", ""},
		{"IN-07", "ANY /number", "src/Controller/Inputs.php", 46, []string{"http.query"}, []string{"n"}, "", "typed_conversion", ""},
		{"IN-08", "ANY /body", "src/Controller/Inputs.php", 51, []string{"http.body"}, nil, "", "", ""},
		{"IN-09", "ANY /post/{post}", "src/Controller/Inputs.php", 56, []string{"storage"}, nil, "php-sql:post.title", "", ""},
		{"IN-10", "ANY /me", "src/Controller/Inputs.php", 61, []string{"storage"}, nil, "php-sql:user.name", "", ""},
		{"IN-11", "ANY /service", "src/Controller/Services.php", 15, []string{"http.path_query_or_form"}, []string{"a"}, "", "helper_definition", ""},
		{"IN-12", "ANY /configuration", "src/OptionalGreeting.php", 12, []string{"http.path_query_or_form"}, []string{"a"}, "", "configuration_precondition", ""},
		{"IN-13", "POST /method", "src/Controller/Inputs.php", 67, []string{"http.path_query_or_form"}, []string{"a"}, "", "", ""},
		{"IN-14", "ANY /unknown", "src/Controller/Services.php", 25, []string{"http.path_query_or_form"}, []string{"a"}, "", "", "php_call_unresolved"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			report := inputs
			if tc.file == "src/Controller/Services.php" || tc.file == "src/OptionalGreeting.php" {
				report = services
			}
			use := symfonyInputUse(t, report, tc.entry, tc.file, tc.line)
			facts := use.InputFacts
			if use.Components == nil || !slices.ContainsFunc(use.Components.Components, func(ref analysis.ComponentRef) bool { return ref.ID == "source.symfony-input-v1" }) {
				t.Fatalf("missing Symfony source component: %+v", use.Components)
			}
			if facts == nil || facts.Version != 1 || facts.Framework != "symfony" {
				t.Fatalf("invalid Symfony input facts: %+v", facts)
			}
			var origins, fields []string
			for _, v := range facts.Values {
				origins = append(origins, v.Origin)
				dep := use.Dependencies[v.Dependency]
				if tc.storage != "" {
					if dep.Source.Kind != "storage_source" || dep.StorageKey != tc.storage {
						t.Fatalf("storage dependency: %+v", dep)
					}
				} else if dep.Source.Kind != "input_source" {
					t.Fatalf("input dependency: %+v", dep)
				}
			}
			for _, stage := range facts.Stages {
				if stage.Name == "request_field" {
					fields = append(fields, stage.Scope)
				}
			}
			if !slices.Equal(origins, tc.origins) || !slices.Equal(fields, tc.fields) {
				t.Fatalf("origins=%v fields=%v, want origins=%v fields=%v", origins, fields, tc.origins, tc.fields)
			}
			if tc.control != "" && !slices.ContainsFunc(facts.Controls, func(e analysis.Evidence) bool { return e.Kind == tc.control }) {
				t.Fatalf("missing control %s", tc.control)
			}
			if tc.gap != "" && !hasSymfonyGap(use.Gaps, tc.gap) {
				t.Fatalf("missing gap %s", tc.gap)
			}
			if tc.id == "IN-13" {
				for _, entry := range report.Entries {
					if entry.Name != "GET /method" {
						continue
					}
					for _, candidate := range report.Uses {
						if candidate.EntryID == entry.ID {
							t.Fatal("POST branch executed under GET")
						}
					}
					return
				}
				t.Fatal("GET route is missing")
			}
		})
	}
}

func symfonyInputUse(t *testing.T, report *analysis.AnalysisReport, name, file string, line int) analysis.CandidateUse {
	t.Helper()
	for _, entry := range report.Entries {
		if entry.Name != name {
			continue
		}
		for _, use := range report.Uses {
			span := use.Sink.Span
			if use.EntryID == entry.ID && use.Kind == "xss_candidate" && span.File == file && span.StartLine == line {
				return use
			}
		}
	}
	t.Fatalf("missing XSS candidate at %s:%d under %s", file, line, name)
	return analysis.CandidateUse{}
}
