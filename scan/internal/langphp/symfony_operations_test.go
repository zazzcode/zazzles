package langphp

import (
	"slices"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSymfonyOperations(t *testing.T) {
	report := symfonyCaseReport(t, "operations")
	checkSymfonyOperationComponents(t, report)
	const controller = "src/Controller/Operations.php"
	const upload = "file_upload_candidate"
	const template = "template_injection_candidate"
	const deserialize = "deserialization_candidate"
	const redirect = "open_redirect_candidate"
	const code = "code_execution_candidate"
	for _, tc := range []struct {
		id, entry, kind, contract, file string
		line                            int
		check                           func(*testing.T, analysis.CandidateUse)
	}{
		{"UP-01", "ANY /upload-client-extension", upload, "symfony-uploaded-file-move-v1", controller, 16, checkSymfonyUpload("mixed", "client", "yes", 0)},
		{"UP-02", "ANY /upload-list", upload, "symfony-uploaded-file-move-v1", controller, 26, checkSymfonyUpload("unknown", "allow_listed", "yes", 1)},
		{"UP-03", "ANY /upload-original-name", upload, "symfony-uploaded-file-move-v1", controller, 33, checkSymfonyUpload("client", "client", "no", 0)},
		{"UP-04", "ANY /upload-temporary-name", upload, "symfony-uploaded-file-move-v1", controller, 39, checkSymfonyUpload("server_generated", "unknown", "yes", 0)},
		{"TI-01", "GET /card/{card}", template, "php-template-source-v1", "src/CardExtension.php", 14, func(t *testing.T, use analysis.CandidateUse) {
			if !slices.ContainsFunc(use.Dependencies, func(d analysis.Dependency) bool {
				return d.StorageKey == "php-sql:Card.text" && d.Source.Kind == "input_source" && d.Source.Span.File == controller && d.Source.Span.StartLine == 45
			}) {
				t.Fatalf("template source lacks POST /card writer: %+v", use.Dependencies)
			}
			checkSymfonyTemplateTransfer(t, use, "templates/stored.html.twig")
		}},
		{"TI-02", "ANY /preview", template, "php-template-source-v1", "src/CardExtension.php", 14, func(t *testing.T, use analysis.CandidateUse) {
			checkSymfonyOperationSource(t, use, "http.query", "caption")
			checkSymfonyTemplateTransfer(t, use, "templates/query.html.twig")
		}},
		{"TI-03", "ANY /example", template, "", "", 0, nil},
		{"DS-01", "ANY /settings-with-template", deserialize, "php-unserialize-v1", "src/Settings.php", 6, checkSymfonySettingsCookie},
		{"DS-02", "ANY /settings-inactive", deserialize, "", "", 0, nil},
		{"DS-03", "ANY /settings-injected", deserialize, "php-unserialize-v1", "src/Settings.php", 6, checkSymfonySettingsCookie},
		{"RD-01", "ANY /redirect-helper", redirect, "symfony-redirect-v1", controller, 81, func(t *testing.T, use analysis.CandidateUse) {
			checkSymfonyOperationSource(t, use, "http.query", "next")
		}},
		{"RD-02", "ANY /redirect-response", redirect, "symfony-redirect-v1", controller, 86, nil},
		{"RD-03", "ANY /redirect-route", redirect, "", "", 0, nil},
		{"RD-04", "ANY /redirect-literal", redirect, "", "", 0, nil},
		{"CD-01", "ANY /evaluate-request", code, "php-eval-v1", controller, 101, nil},
		{"CD-02", "ANY /evaluate-literal", code, "", "", 0, nil},
	} {
		t.Run(tc.id, func(t *testing.T) {
			uses := symfonyOperationsForEntry(t, report, tc.entry, tc.kind)
			if tc.contract == "" {
				if len(uses) != 0 {
					t.Fatalf("unexpected %s candidate at %+v", tc.kind, uses[0].Sink.Span)
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("got %d %s candidates under %s; want one at %s:%d", len(uses), tc.kind, tc.entry, tc.file, tc.line)
			}
			use := uses[0]
			if at := use.Sink.Span; at.File != tc.file || at.StartLine != tc.line {
				t.Fatalf("sink %+v; want %s:%d", at, tc.file, tc.line)
			}
			if use.APIModel == nil || use.APIModel.ID != tc.contract {
				t.Fatalf("contract %+v; want %s", use.APIModel, tc.contract)
			}
			if tc.check != nil {
				tc.check(t, use)
			}
			if tc.kind == upload {
				checkSymfonyUploadPath(t, report, tc.entry, use, tc.id != "UP-04")
			}
		})
	}
}

func checkSymfonyOperationComponents(t *testing.T, report *analysis.AnalysisReport) {
	t.Helper()
	for _, u := range report.Uses {
		if u.Components == nil || u.Components.Failure != "" {
			t.Errorf("%s at %+v could not select components: %+v", u.Kind, u.Sink.Span, u.Components)
		}
	}
}

func checkSymfonyUploadPath(t *testing.T, report *analysis.AnalysisReport, entry string, upload analysis.CandidateUse, hasPath bool) {
	t.Helper()
	uses := symfonyOperationsForEntry(t, report, entry, "path_traversal_candidate")
	if !hasPath {
		if len(uses) != 0 {
			t.Fatalf("temporary filename produced a path candidate: %+v", uses[0].Sink.Span)
		}
		return
	}
	if len(uses) != 1 {
		t.Fatalf("got %d path candidates; want one", len(uses))
	}
	u := uses[0]
	if u.Sink.Span != upload.Sink.Span || u.Path == nil || u.Path.Role != "write" || u.Path.ContractID != upload.Upload.ContractID {
		t.Fatalf("missing upload path write: %+v", u.Path)
	}
	if len(u.Path.Operands) != 2 || u.Path.Operands[0].Slot != analysis.PathSlotFile || u.Path.Operands[1].Slot != analysis.PathSlotDestination {
		t.Fatalf("expected directory and name operands: %+v", u.Path.Operands)
	}
	for _, operand := range u.Path.Operands {
		if len(operand.Context) != 1 || u.Context[operand.Context[0]].Kind != "path_operand" {
			t.Fatalf("missing path operand evidence: %+v", operand)
		}
	}
}

func checkSymfonyUpload(name, extension, served string, controls int) func(*testing.T, analysis.CandidateUse) {
	return func(t *testing.T, use analysis.CandidateUse) {
		t.Helper()
		f := use.Upload
		if f == nil || f.StoredName != name || f.ExtensionOrigin != extension || f.DestinationServed != served {
			t.Fatalf("upload facts %+v; want stored_name=%s extension_origin=%s destination_served=%s", f, name, extension, served)
		}
		if len(f.TypeControls) != controls {
			t.Fatalf("got %d type controls; want %d", len(f.TypeControls), controls)
		}
		if controls > 0 {
			c := f.TypeControls[0]
			if c.Kind != analysis.UploadExtensionAllowList || c.ClientControlled || use.Context[c.Context].Span.StartLine != 23 {
				t.Fatalf("missing rejecting membership check: %+v", c)
			}
		}
		if !slices.ContainsFunc(use.Dependencies, func(d analysis.Dependency) bool {
			return d.Source.Kind == "input_source" && d.SinkSlot == "upload_content"
		}) {
			t.Fatal("upload content has no request path")
		}
	}
}

func checkSymfonyTemplateTransfer(t *testing.T, use analysis.CandidateUse, template string) {
	t.Helper()
	if !slices.ContainsFunc(use.Dependencies, func(d analysis.Dependency) bool {
		return slices.ContainsFunc(d.Transfers, func(e analysis.Evidence) bool {
			return e.Span.File == template && e.Span.StartLine == 1
		})
	}) {
		t.Fatalf("template region transfer from %s missing", template)
	}
}

func checkSymfonySettingsCookie(t *testing.T, use analysis.CandidateUse) {
	t.Helper()
	checkSymfonyOperationSource(t, use, "http.cookies", "p")
}

func checkSymfonyOperationSource(t *testing.T, use analysis.CandidateUse, origin, name string) {
	t.Helper()
	if use.InputFacts == nil || !slices.ContainsFunc(use.InputFacts.Values, func(v analysis.InputValueFact) bool { return v.Origin == origin }) ||
		!slices.ContainsFunc(use.InputFacts.Stages, func(s analysis.InputStage) bool { return s.Scope == name }) {
		t.Fatalf("missing %s input %s: %+v", origin, name, use.InputFacts)
	}
}

func symfonyOperationsForEntry(t *testing.T, report *analysis.AnalysisReport, entry, kind string) []analysis.CandidateUse {
	t.Helper()
	for _, e := range report.Entries {
		if e.Name != entry {
			continue
		}
		var uses []analysis.CandidateUse
		for _, u := range report.Uses {
			if u.EntryID == e.ID && u.Kind == kind {
				uses = append(uses, u)
			}
		}
		return uses
	}
	t.Fatalf("missing entry %s", entry)
	return nil
}
