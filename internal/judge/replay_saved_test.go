package judge

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
)

// TestReplaySavedRun replays every saved decision of one retained live run offline
// (no network) against a FRESH analysis of the pinned target source: the exact
// request must still match, and the current decoder and policy must reproduce each
// saved assessment. It runs only when ZAZZ_REPLAY_RUN (findings.json),
// ZAZZ_REPLAY_TRACES and ZAZZ_REPLAY_ROOT (target checkout) are set.
func TestReplaySavedRun(t *testing.T) {
	file, traces := os.Getenv("ZAZZ_REPLAY_RUN"), os.Getenv("ZAZZ_REPLAY_TRACES")
	root := os.Getenv("ZAZZ_REPLAY_ROOT")
	if file == "" || traces == "" || root == "" {
		t.Skip("set ZAZZ_REPLAY_RUN, ZAZZ_REPLAY_TRACES and ZAZZ_REPLAY_ROOT to replay a retained run")
	}
	fresh, err := parse.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]analysis.CandidateUse{}
	for _, u := range fresh.Uses {
		byID[u.ID] = u
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var r analysis.AnalysisReport
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	c, _ := New("openai", "gpt-6-luna", "replay-only")
	replayed, mismatched, absent := 0, 0, 0
	for _, saved := range r.Uses {
		if saved.Assessment.Status != "completed" {
			continue
		}
		u, ok := byID[saved.ID]
		if !ok {
			mismatched++
			t.Errorf("%s: saved use is absent from the fresh analysis", saved.ID)
			continue
		}
		name := strings.NewReplacer(":", "_", "/", "_", "\\", "_").Replace(saved.ID) + ".json"
		data, err := os.ReadFile(filepath.Join(traces, name))
		if err != nil {
			absent++
			continue
		}
		var trace DecisionTrace
		if err := json.Unmarshal(data, &trace); err != nil {
			t.Fatal(err)
		}
		got := c.Replay(u, trace)
		if got.Status != "completed" || got.FindingStatus != saved.Assessment.FindingStatus || !reflect.DeepEqual(got.Answers, saved.Assessment.Answers) || got.RequestDigest != saved.Assessment.RequestDigest {
			mismatched++
			t.Errorf("%s: replay %s/%s want %s (%s)", u.ID, got.Status, got.FindingStatus, saved.Assessment.FindingStatus, got.Reason)
			continue
		}
		replayed++
	}
	t.Logf("REPLAY replayed=%d mismatched=%d trace-absent=%d", replayed, mismatched, absent)
	if absent > 0 {
		t.Errorf("%d completed assessments have no saved trace", absent)
	}
}
