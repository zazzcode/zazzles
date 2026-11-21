package analysispacks_test

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
)

func TestDeserializationSelection(t *testing.T) {
	for _, row := range []struct{ path, source, file, contract string }{
		{"langpy", "python", "app.py", analysispacks.PythonPickle},
		{"langjs", "node", "js/app.js", analysispacks.NodeSerialize},
		{"langjs", "node", "ts/app.ts", analysispacks.NodeSerialize},
		{"langphp", "php", "php-01.php", analysispacks.PHPUnserialize},
	} {
		t.Run(row.file, func(t *testing.T) {
			root := filepath.Join("..", row.path, "testdata", "deserialization")
			r, err := pipeline.AnalyzeWithOptions(root, row.file, nil, pipeline.Options{})
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(r.Uses, func(u analysis.CandidateUse) bool {
				return u.Kind == analysis.DeserializationKind && u.APIModel != nil && u.APIModel.ID == row.contract
			})
			if i == -1 {
				t.Fatal("missing fixture candidate")
			}
			u := r.Uses[i]
			got, err := analysispacks.Select(u)
			if err != nil {
				t.Fatal(err)
			}
			want := "source." + row.source + "-input-deserialization-v1"
			if got.Pack.ID != "pack.deserialization" || !slices.ContainsFunc(got.Components, func(ref analysis.ComponentRef) bool { return ref.ID == want }) {
				t.Fatalf("selection missing %s: %+v", want, got)
			}
			material, err := analysispacks.ForUse(u)
			if err != nil || len(material.Questions) != 4 {
				t.Fatalf("wrong question set: %+v (%v)", material, err)
			}
			browser := u
			browser.EntryKind, browser.EntryFacts = "browser", nil
			if _, err := analysispacks.Select(browser); err == nil {
				t.Error("browser entry selected")
			}
			if row.source == "node" {
				u.APIModel = analysispacks.DeserializationContract(analysispacks.PHPUnserialize)
			} else {
				u.APIModel = analysispacks.DeserializationContract(analysispacks.NodeSerialize)
				if row.source == "php" {
					u.APIModel = analysispacks.DeserializationContract(analysispacks.PythonPickle)
				}
			}
			if _, err := analysispacks.Select(u); err == nil {
				t.Error("cross-language contract selected")
			}
		})
	}
}
