package guidelines

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/lang"
)

// The SQL projection's effective bytes are frozen from the accepted SQL tree.
// A refactor of section selection must not change what SQL requests receive;
// a deliberate content change needs an explicit version bump instead.
func TestFamilyGuidanceCompleteness(t *testing.T) {
	frozen := map[string]struct {
		version string
		sum     string
	}{"javascript": {"5", "3c5b4338ec16a88f7386e884554985102e63a420ee1c5e7907b452320dd58fbc"}, "python": {"3", "022ac11f28aedcd5e4f1255dfb6ca62f7eaa57dad083f37d119b9d68d4b48eb4"}}
	for _, l := range []lang.Language{lang.JavaScript, lang.TypeScript, lang.Python} {
		g, err := FamilyBody(l, "sql")
		if err != nil {
			t.Fatalf("sql %s: %v", l, err)
		}
		want, ok := frozen[g.ID]
		if !ok || g.Version != want.version || fmt.Sprintf("%x", sha256.Sum256([]byte(g.Body))) != want.sum {
			t.Fatalf("sql %s projection bytes drifted", l)
		}
	}
	noSQL, err := FamilyBody(lang.TypeScript, "nosql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Posture", "## Validation", "## Free text", "## Sinks", "## Do not claim", "## Evidence and human-readable results", "`$where` string", "`Array.find` is not a NoSQL query", "A NoSQL document accepting a value"} {
		if !strings.Contains(noSQL.Body, want) {
			t.Fatalf("nosql guidance lost %q", want)
		}
	}
	for _, unwanted := range []string{"## Logging", "Cross-site scripting", "Logging a SQL-looking string", "ORM search value"} {
		if strings.Contains(noSQL.Body, unwanted) {
			t.Fatalf("nosql guidance kept unrelated %q", unwanted)
		}
	}
	validationJS, err := FamilyBody(lang.JavaScript, "validation")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"## Posture", "## Validation", "## Free text", "## Do not claim", "## Evidence and human-readable results", "No validator identified in a bounded slice"} {
		if !strings.Contains(validationJS.Body, want) {
			t.Fatalf("javascript validation guidance lost %q", want)
		}
	}
	for _, unwanted := range []string{"## Sinks", "`$where`", "## Logging", "Cross-site scripting", "Use NoSQL as one word"} {
		if strings.Contains(validationJS.Body, unwanted) {
			t.Fatalf("validation guidance kept sink/query material %q", unwanted)
		}
	}
	validationPy, err := FamilyBody(lang.Python, "validation")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"A missing check alone does not establish a business requirement", "## Free text"} {
		if !strings.Contains(validationPy.Body, want) {
			t.Fatalf("python validation guidance lost %q", want)
		}
	}
	for _, unwanted := range []string{"## Sinks", "DB-API", "## Rendering", "## Logging"} {
		if strings.Contains(validationPy.Body, unwanted) {
			t.Fatalf("python validation guidance kept unrelated %q", unwanted)
		}
	}
	for _, family := range []string{"sql", "nosql", "validation"} {
		if _, err := FamilyBody(lang.Go, family); err == nil {
			t.Fatalf("%s guidance claimed for unsupported Go sources", family)
		}
	}
	if _, err := FamilyBody(lang.Python, "nosql"); err == nil {
		t.Fatal("nosql guidance claimed for the unimplemented Python adapter")
	}

	// A renamed, missing or duplicated required section must fail the projection
	// instead of silently omitting interpretation while still producing a digest.
	js, _ := ForLanguage(lang.JavaScript)
	renamed := strings.Replace(js.Body, "## Free text", "## Free-form text", 1)
	if _, err := project(renamed, validationSpec()); err == nil {
		t.Fatal("renamed required section accepted")
	}
	if _, err := project(strings.Replace(js.Body, "## Do not claim", "## Removed", 1), validationSpec()); err == nil {
		t.Fatal("missing required section accepted")
	}
	duplicated := js.Body + "\n## Posture\n\nDuplicate posture section.\n"
	if _, err := project(duplicated, noSQLSpec()); err == nil {
		t.Fatal("duplicate required section accepted")
	}
	// A canonical-document edit that removes a phrase a family projection must
	// rewrite is a completeness failure, not a silent content change.
	if _, err := project(strings.Replace(js.Body, "Logging a SQL-looking string is not a query. ", "", 1), noSQLSpec()); err == nil {
		t.Fatal("missing required nosql phrase edit accepted")
	}
}
