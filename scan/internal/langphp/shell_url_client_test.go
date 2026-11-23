package langphp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

const shellURLFixture = "testdata/shell-url-client"

func shellClientUses(r *analysis.AnalysisReport, sink string) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "ssrf_candidate" && at(u.Sink.Span) == sink && u.Outbound != nil && u.Outbound.Transport == "shell_client" {
			out = append(out, u)
		}
	}
	return out
}

func TestPHPShellURLClient(t *testing.T) {
	r := phpAnalyze(t, shellURLFixture, "")
	type want struct {
		program, operand string
		// source is the text of the request source that reaches the URL word.
		source string
		// context are evidence kinds the candidate must carry.
		context []string
		prefix  string
	}
	for _, tt := range []struct {
		name, sink string
		want       *want
	}{
		{"SU-01 concatenated curl URL", "su01.php:2", &want{program: "curl", source: "$_GET['u']"}},
		{"SU-02 interpolated wget URL", "su02.php:3", &want{program: "wget", source: "$_GET['u']"}},
		{"SU-03 escapeshellarg leaves the request", "su03.php:3", &want{program: "curl", source: "$_GET['u']"}},
		{"SU-04 the value of -o is not a URL", "su04.php:3", nil},
		{"SU-05 the value of -H is not a URL", "su05.php:3", nil},
		{"SU-06 the value of -x is a proxy", "su06.php:3", &want{program: "curl", operand: "proxy", source: "$_GET['p']"}},
		{"SU-07 literal origin prefix", "su07.php:3", &want{program: "curl", source: "$_GET['id']", context: []string{"destination_prefix"}, prefix: "https://api.example.org/items/"}},
		{"SU-08 convert is not a URL client", "su08.php:3", nil},
		{"SU-09 the program is not literal", "su09.php:4", nil},
		{"SU-10 Process argv", "app/src/Controller/FetchController.php:16", &want{program: "curl", source: "$request->query->get('u')"}},
		{"SU-11 Process argv, the value of -o", "app/src/Controller/FetchController.php:24", nil},
		{"SU-12 filter_var guard evidence", "app/src/Service/Pinger.php:16", &want{program: "curl", source: "$request->headers->get('referer')", context: []string{"php_filter_filter_validate_url"}}},
		{"SU-13 backticks", "su13.php:3", &want{program: "curl", source: "$_GET['u']"}},
		{"SU-14 Symfony service reached from an action", "app/src/Service/Pinger.php:8", &want{program: "curl", source: "$request->headers->get('referer')"}},
		{"an option written with = takes no next word", "option-equals.php:2", &want{program: "wget", source: "$_GET['u']"}},
		{"a long alias of a value option", "option-long.php:2", nil},
		{"a command held in a variable", "variable.php:3", &want{program: "curl", source: "$_GET['u']"}},
		{"a variable command keeps each word's own value", "variable-option.php:3", &want{program: "curl", source: "$_GET['u']"}},
		{"--proxy= with the value attached", "proxy-equals.php:2", &want{program: "curl", operand: "proxy", source: "$_GET['p']"}},
		{"Process argv, --proxy= with the value attached", "app/src/Controller/FetchController.php:38", &want{program: "curl", operand: "proxy", source: "$request->query->get('p')"}},
		{"convert with a nested request", "nested-sink.php:2", nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := shellClientUses(r, tt.sink)
			if tt.want == nil {
				if len(got) != 0 {
					t.Fatalf("%d shell-client candidates, want none: %+v", len(got), got[0].Outbound)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%d shell-client candidates, want 1", len(got))
			}
			u := got[0]
			if u.Outbound.Operation != tt.want.program || u.Outbound.Operand != tt.want.operand || u.Outbound.ContractID != analysispacks.PHPShellURLClient || u.APIModel == nil || u.APIModel.ID != analysispacks.PHPShellURLClient {
				t.Fatalf("outbound %+v model %+v", u.Outbound, u.APIModel)
			}
			if len(u.Dependencies) != 1 || u.Dependencies[0].Source.Text != tt.want.source || u.Dependencies[0].SinkSlot != analysis.OutboundSlotDestination {
				t.Fatalf("dependencies %+v, want one from %s", u.Dependencies, tt.want.source)
			}
			if err := u.Outbound.Validate(len(u.Dependencies), len(u.Context)); err != nil {
				t.Fatalf("outbound facts: %v", err)
			}
			if u.Completeness == nil || len(u.Completeness.Evidence["destination_operand"]) == 0 || len(u.Completeness.Blockers) != 0 {
				t.Fatalf("completeness lacks the destination operand or has blockers")
			}
			for _, kind := range tt.want.context {
				i := slices.IndexFunc(u.Context, func(e analysis.Evidence) bool { return e.Kind == kind })
				if i < 0 {
					t.Fatalf("context lacks %s", kind)
				}
				if kind == "destination_prefix" && u.Context[i].Text != tt.want.prefix {
					t.Fatalf("prefix %q", u.Context[i].Text)
				}
			}
		})
	}
	t.Run("SU-03 the command candidate keeps its quoting evidence", func(t *testing.T) {
		for _, u := range r.Uses {
			if u.Kind == "command_execution_candidate" && at(u.Sink.Span) == "su03.php:3" {
				if len(u.Command.Paths) != 1 || u.Command.Paths[0].Protection != "guarded" {
					t.Fatalf("paths %+v", u.Command.Paths)
				}
				return
			}
		}
		t.Fatal("no command candidate")
	})
	t.Run("SU-14 is under the action's entry", func(t *testing.T) {
		u := shellClientUses(r, "app/src/Service/Pinger.php:8")[0]
		for _, e := range r.Entries {
			if e.ID == u.EntryID && strings.Contains(e.Name, "/su14") {
				return
			}
		}
		t.Fatalf("entry %s is not the /su14 action", u.EntryID)
	})
}

// TestCommandCandidateUnchanged proves the contract adds records and
// changes none: with it off, every other record is byte-identical. The
// fixture includes commands whose operand holds another sink, which a
// second evaluation of the operand would record twice.
func TestCommandCandidateUnchanged(t *testing.T) {
	for _, fixture := range []string{shellURLFixture, "testdata/symfony/services-ops", "testdata/command"} {
		with := phpAnalyze(t, fixture, "")
		shellURLContract = false
		without := phpAnalyze(t, fixture, "")
		shellURLContract = true
		var kept []analysis.CandidateUse
		added, commands := 0, 0
		for _, u := range with.Uses {
			if u.Outbound != nil && u.Outbound.Transport == "shell_client" {
				added++
				continue
			}
			if u.Kind == "command_execution_candidate" {
				commands++
			}
			kept = append(kept, u)
		}
		a, _ := json.Marshal(kept)
		b, _ := json.Marshal(without.Uses)
		if string(a) != string(b) {
			t.Errorf("%s: records differ with the contract on (%d) and off (%d)", fixture, len(kept), len(without.Uses))
		}
		if commands == 0 || (fixture == shellURLFixture && added == 0) {
			t.Errorf("%s: %d command candidates, %d shell-client candidates", fixture, commands, added)
		}
	}
}
