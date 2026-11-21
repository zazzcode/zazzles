package analysispacks

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/lang"
)

func ssrfSelectionUse(file, contract string) analysis.CandidateUse {
	return analysis.CandidateUse{Kind: "ssrf_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}}, APIModel: SSRFContract(contract),
		Completeness: &analysis.Completeness{ClaimKind: "ssrf", Required: []string{"input_source", "sink_binding", "invoked_callable", "control_flow", "destination_operand"}, Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
}

func TestSSRFComponentSelection(t *testing.T) {
	for _, tt := range []struct {
		file, contract, language string
	}{
		{"server.js", FetchURLContract, "language.ssrf.javascript"},
		{"server.ts", AxiosURLContract, "language.ssrf.javascript"},
		{"app.py", PythonHTTPURLContract, "language.ssrf.python"},
	} {
		s, err := Select(ssrfSelectionUse(tt.file, tt.contract))
		if err != nil {
			t.Fatalf("%s: %v", tt.contract, err)
		}
		var ids []string
		for _, c := range s.Components {
			ids = append(ids, c.ID)
		}
		got := strings.Join(ids, ",")
		for _, want := range []string{"pack.ssrf", "claim.ssrf", "evidence.ssrf", "flow.ssrf", "entry.http", tt.language, "api." + tt.contract} {
			if !strings.Contains(got, want) {
				t.Fatalf("%s selection lacks %s: %s", tt.contract, want, got)
			}
		}
		m, err := ForUse(analysis.CandidateUse{Kind: "ssrf_candidate", EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: tt.file}}, APIModel: SSRFContract(tt.contract), Completeness: ssrfSelectionUse(tt.file, tt.contract).Completeness, Components: s})
		if err != nil || len(m.Questions) != 3 || m.Contract.ID != tt.contract {
			t.Fatalf("%s material: %v %+v", tt.contract, err, m)
		}
	}
	// No verified binding, a conflicting contract or a non-HTTP Python entry is not selected.
	missing := ssrfSelectionUse("server.js", FetchURLContract)
	missing.Completeness.Evidence = map[string][]analysis.Evidence{}
	if _, err := Select(missing); err == nil {
		t.Fatal("selection without a verified binding")
	}
	conflict := ssrfSelectionUse("server.js", FetchURLContract)
	conflict.APIModel = &analysis.APIModel{ID: FetchURLContract, Library: "fetch"}
	if _, err := Select(conflict); err == nil {
		t.Fatal("selection with a drifted contract")
	}
	grpc := ssrfSelectionUse("app.py", PythonHTTPURLContract)
	grpc.EntryKind = "grpc"
	if _, err := Select(grpc); err == nil {
		t.Fatal("Python SSRF selected for a non-HTTP entry")
	}
	if FamilySlugForKind("ssrf_candidate") != "ssrf" || !ValidCLIFamily("ssrf") {
		t.Fatal("ssrf CLI family not registered")
	}
	for _, l := range []lang.Language{lang.JavaScript, lang.Python} {
		if c := embedded.components[languageID(FamilyForName("ssrf"), l)]; c.Material == "" {
			t.Fatalf("missing %s guidance", l)
		}
	}
}
