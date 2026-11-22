package analysispacks

import (
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"strings"
	"testing"
)

func TestCodeRedirectSelection(t *testing.T) {
	for _, family := range []string{"code", "redirect"} {
		for _, file := range []string{"server.js", "client.tsx", "app.py", "index.php"} {
			for _, id := range contractIDs(FamilyForName(family)) {
				f := FamilyForName(family)
				u := analysis.CandidateUse{Kind: f.Kinds[0], EntryKind: "http", Sink: analysis.Evidence{Span: analysis.Span{File: file}}, APIModel: familyContract(f, id), Completeness: &analysis.Completeness{ClaimKind: family, Evidence: map[string][]analysis.Evidence{"sink_binding": {{Kind: "sink_binding"}}}}}
				if file == "client.tsx" {
					u.EntryKind = "browser"
				}
				if (file == "app.py") != strings.HasPrefix(id, "python-") || (file == "index.php") != (strings.HasPrefix(id, "php-") || id == SymfonyRedirectContract) {
					if _, err := Select(u); err == nil {
						t.Fatal("language/API conflict selected")
					}
					continue
				}
				Attach(&u)
				if u.Components.Failure != "" {
					t.Fatal(u.Components.Failure)
				}
				material, err := ForUse(u)
				if err != nil || len(material.Questions) != 3 || material.Contract.ID != id {
					t.Fatalf("%s %s %s material=%+v err=%v", family, file, id, material, err)
				}
				u.APIModel.Semantics = "forged"
				if _, err := Select(u); err == nil {
					t.Fatal("forged contract selected")
				}
			}
		}
		if !ValidCLIFamily(family) {
			t.Fatalf("CLI family %s absent", family)
		}
	}
}
