package judge

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// groupedXSS is one rendering claim whose two request paths come from two
// dispatch-alternative files.
var groupedXSS = map[string]string{
	"index.php": `<?php
$html = "";
if ($_GET['level'] == 'low') {
	include 'source/low.php';
} else {
	include 'source/high.php';
}
echo $html;
`,
	"source/low.php":  "<?php\n$html .= '<p>' . $_GET['name'] . '</p>';\n",
	"source/high.php": "<?php\n$html .= '<p>' . $_POST['name'] . '</p>';\n",
}

func groupedUse(t *testing.T) analysis.CandidateUse {
	t.Helper()
	_, u := parsedXSS(t, groupedXSS)
	files := map[string]bool{}
	for _, d := range u.Dependencies {
		files[d.Source.Span.File] = true
	}
	if !files["source/low.php"] || !files["source/high.php"] {
		t.Fatalf("fixture wants sources in both alternatives: %+v", u.Dependencies)
	}
	return u
}

// TestPathGroupCombination (close-findings-gaps AC5, D-14): one Confirmed
// group is Confirmed; Protected needs every group Protected; anything else
// is Review.
func TestPathGroupCombination(t *testing.T) {
	g := func(status string) analysis.PathGroupResult {
		r := analysis.PathGroupResult{Status: "completed", FindingStatus: status}
		if status == "" {
			r = analysis.PathGroupResult{Status: "not_run", Reason: pathGroupCap}
		}
		return r
	}
	for _, tt := range []struct {
		name   string
		groups []analysis.PathGroupResult
		want   string
	}{
		{"one Confirmed group is Confirmed", []analysis.PathGroupResult{g("needs_evidence"), g("confirmed_vulnerability")}, "confirmed_vulnerability"},
		{"every group Protected is Protected", []analysis.PathGroupResult{g("protected_for_claim"), g("protected_for_claim")}, "protected_for_claim"},
		{"Protected beside unknown is Review", []analysis.PathGroupResult{g("protected_for_claim"), g("needs_evidence")}, "needs_evidence"},
		{"Protected beside an unjudged group is Review", []analysis.PathGroupResult{g("protected_for_claim"), g("")}, "needs_evidence"},
		{"no judged group is Review", []analysis.PathGroupResult{g(""), g("")}, "needs_evidence"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			status, _ := combinePathGroups(tt.groups)
			if status != tt.want {
				t.Fatalf("combined %s, want %s", status, tt.want)
			}
		})
	}
}

// TestPathGroupRequests (AC5): an over-limit XSS record is sent as one
// ordinary request per path group, each under the limit and naming the
// withheld paths; a raw witness in one group is Confirmed for the record.
func TestPathGroupRequests(t *testing.T) {
	u := groupedUse(t)
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	full, _ := c.payload(u)
	var mu sync.Mutex
	var bodies []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(raw))
		mu.Unlock()
		if len(raw) > requestLimit {
			t.Errorf("an over-limit request reached the transport: %d", len(raw))
		}
		w.Write(xssAnswer(u, "openai", "raw"))
	}))
	defer server.Close()
	c.UseEndpoint(server.URL, server.Client())
	// Lower the limit below the whole record but above each group.
	withRequestLimit(t, len(full)-1)
	groups, ok := c.planPathGroups(u)
	if !ok || len(groups) != 2 {
		t.Fatalf("want two path groups, got %+v %v", groups, ok)
	}
	a := c.Assess(context.Background(), u)
	if len(bodies) != 2 {
		t.Fatalf("want one request per group, got %d", len(bodies))
	}
	for _, b := range bodies {
		if !strings.Contains(b, "path_group_omitted") || !strings.Contains(b, "withheld") {
			t.Fatalf("a group request must name its omitted paths: %.300s", b)
		}
	}
	if len(a.PathGroups) != 2 || a.FindingStatus != "confirmed_vulnerability" {
		t.Fatalf("status %s groups %+v reason %q", a.FindingStatus, a.PathGroups, a.Reason)
	}
	for _, g := range a.PathGroups {
		if g.RequestBytes > requestLimit || g.RequestDigest == "" || len(g.Omitted) == 0 {
			t.Fatalf("group %+v", g)
		}
	}
	// A record under the limit is unchanged: one request, no groups.
	withRequestLimit(t, len(full)+1)
	bodies = nil
	b := c.Assess(context.Background(), u)
	if len(bodies) != 1 || len(b.PathGroups) != 0 {
		t.Fatalf("an in-limit record keeps its single request: %d requests, groups %+v", len(bodies), b.PathGroups)
	}
}

// TestPathGroupReplayAndLimit (D-15): each group request replays alone, and a
// path-group record counts one request per group against the judge limit.
func TestPathGroupReplayAndLimit(t *testing.T) {
	r, u := parsedXSS(t, groupedXSS)
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	full, _ := c.payload(u)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		calls++
		w.Write(xssAnswer(u, "openai", "raw"))
	}))
	defer server.Close()
	c.UseEndpoint(server.URL, server.Client())
	withRequestLimit(t, len(full)-1)
	a, trace := c.AssessTrace(context.Background(), u)
	if len(trace.Groups) != 2 || calls != 2 {
		t.Fatalf("want two group traces and requests, got %d traces %d calls", len(trace.Groups), calls)
	}
	if replay := c.Replay(u, trace); replay.FindingStatus != a.FindingStatus || len(replay.PathGroups) != 2 || replay.RequestDigest != a.RequestDigest {
		t.Fatalf("replay %+v, live %+v", replay, a)
	}
	tampered := trace
	tampered.Groups = append([]DecisionTrace{}, trace.Groups...)
	tampered.Groups[1].Request = trace.Groups[0].Request
	if replay := c.Replay(u, tampered); replay.PathGroups[1].Status == "completed" {
		t.Fatal("a group replays only against its own request")
	}
	for _, limit := range []int{1, 2} {
		calls = 0
		report := *r
		report.Uses = []analysis.CandidateUse{u}
		c.AssessScheduled(context.Background(), &report, ScheduleOptions{Limit: limit})
		got := report.Uses[0].Assessment
		switch limit {
		case 1:
			if calls != 0 || got.Reason != "judge request limit reached" {
				t.Fatalf("limit 1: a two-group record is not started (%d calls, %q)", calls, got.Reason)
			}
		case 2:
			if calls != 2 || len(got.PathGroups) != 2 {
				t.Fatalf("limit 2: %d calls, groups %+v", calls, got.PathGroups)
			}
		}
	}
}
