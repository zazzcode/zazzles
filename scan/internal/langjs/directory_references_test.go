package langjs

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// TestDirectoryReferences covers specification 23: a directory-listing record
// joins every place in the selected modules whose path literal is the listed
// directory or lies under it, at most eight, in file and position order, with
// the enclosing property or call as the evidence. A listing with no such place
// keeps the evidence it had.
func TestDirectoryReferences(t *testing.T) {
	baseline := []string{"mount_path", "directory", "directory_contents", "mount_access", "deployed_file"}
	for _, tt := range []struct {
		name, dir string
		listings  int      // directory-listing records in the fixture
		refs      []string // substrings of the reference evidence text, in order; nil for none
		total     int      // the N the model text states
		skip      string   // a file whose listing record is not checked
	}{
		{"rotating_log_stream", "rotating-log-stream", 1, []string{"path.resolve('logs/rotated')"}, 1, ""},
		{"write_stream", "write-stream", 1, []string{"fs.createWriteStream('logs/app.log'"}, 1, ""},
		{"upload_destination", "upload-destination", 1, []string{"dest: 'uploads/'"}, 1, ""},
		{"backup_path", "backup-path", 1, []string{"target: 'backups/db.sqlite'"}, 1, ""},
		{"own_registrations_are_not_references", "own-registrations-only", 2, nil, 0, ""},
		{"prefix_only", "prefix-only", 1, nil, 0, ""},
		{"dirname_path_is_not_a_reference", "dirname-path", 1, nil, 0, ""},
		{"absolute_literal", "absolute-literal", 1, nil, 0, ""},
		{"unimported_modules_contribute_nothing", "unimported-modules", 2, nil, 0, "snippets/fix.js"},
		{"module_imported_two_levels_deep", "deep-import", 1, []string{"fs.createWriteStream('logs/deep.log')"}, 1, ""},
		{"rooted_path_call", "rooted-call", 1, []string{"res.sendFile(path.resolve('logs/', req.params.name))"}, 1, ""},
		{"at_most_eight", "many-references", 1, []string{"a: 'spool/a.log'", "b:", "c:", "d:", "e:", "f:", "g:", "h:"}, 10, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Analyze(filepath.Join("testdata", "configuration", "listing-refs", tt.dir), "")
			if err != nil {
				t.Fatal(err)
			}
			found := 0
			for _, u := range report.Uses {
				if u.Kind != analysis.ConfigurationKind || u.Configuration.Check != analysis.CheckDirectoryListing {
					continue
				}
				if tt.skip != "" && u.Sink.Span.File == tt.skip {
					found++ // the snippet's own listing legitimately refers to its own module
					continue
				}
				found++
				var kinds, refs []string
				var texts []string
				for _, e := range u.Configuration.Joined {
					kinds = append(kinds, e.Kind)
					if e.Kind == "directory_reference" {
						refs = append(refs, e.Text)
						texts = append(texts, e.ModelText)
					}
				}
				if tt.refs == nil {
					if strings.Join(kinds, ",") != strings.Join(baseline, ",") {
						t.Fatalf("a listing without a reference must keep its evidence: %v", kinds)
					}
					continue
				}
				want := append([]string{}, baseline[:3]...)
				for range tt.refs {
					want = append(want, "directory_reference")
				}
				want = append(want, baseline[3:]...)
				if strings.Join(kinds, ",") != strings.Join(want, ",") {
					t.Fatalf("evidence kinds = %v, want %v", kinds, want)
				}
				for i, sub := range tt.refs {
					if !strings.Contains(refs[i], sub) {
						t.Fatalf("reference %d = %q, want it to contain %q", i, refs[i], sub)
					}
					if !strings.Contains(texts[i], "at "+strconv.Itoa(tt.total)+" places") || !strings.Contains(texts[i], "this is "+strconv.Itoa(i+1)+" of "+strconv.Itoa(tt.total)) {
						t.Fatalf("model text %q does not state %d of %d", texts[i], i+1, tt.total)
					}
				}
			}
			if found != tt.listings {
				t.Fatalf("directory listing records: %d, want %d", found, tt.listings)
			}
		})
	}
}
