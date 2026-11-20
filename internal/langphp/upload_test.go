package langphp

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// TestPHPUploadFacts (close-findings-gaps AC6, D-19, D-20).
func TestPHPUploadFacts(t *testing.T) {
	r := phpAnalyze(t, filepath.Join("testdata", "upload"), "")
	byFile := map[string]analysis.CandidateUse{}
	for _, u := range phpUsesOfKind(r, "file_upload_candidate") {
		byFile[filepath.Base(u.Sink.Span.File)] = u
	}
	for _, tt := range []struct {
		file, stored, extension, served string
		controls                        []string
	}{
		{"raw.php", "client_basename", "client", "yes", nil},
		{"declared.php", "client", "client", "yes", []string{analysis.UploadClientDeclaredType}},
		{"allowlist.php", "client_basename", "allow_listed", "yes", []string{analysis.UploadExtensionAllowList}},
		{"generated.php", "server_generated", "fixed", "yes", nil},
		{"outside.php", "client_basename", "client", "no", nil},
	} {
		t.Run(tt.file, func(t *testing.T) {
			u, ok := byFile[tt.file]
			if !ok {
				t.Fatalf("no file_upload_candidate in %s", tt.file)
			}
			x := u.Upload
			if err := x.Validate(len(u.Dependencies), len(u.Context)); err != nil {
				t.Fatal(err)
			}
			if x.StoredName != tt.stored || x.ExtensionOrigin != tt.extension || x.DestinationServed != tt.served || u.APIModel == nil || u.APIModel.ID != analysispacks.PHPMoveUploadedFile {
				t.Fatalf("facts %+v", x)
			}
			var kinds []string
			for _, c := range x.TypeControls {
				kinds = append(kinds, c.Kind)
			}
			if len(kinds) != len(tt.controls) || len(kinds) > 0 && kinds[0] != tt.controls[0] {
				t.Fatalf("controls %v, want %v", kinds, tt.controls)
			}
			if _, err := analysispacks.Select(u); err != nil {
				t.Fatalf("selection rejects the record: %v", err)
			}
		})
	}
}
