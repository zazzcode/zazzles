package judge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/parse"
	"github.com/zazzcode/zazzles/internal/report"
)

func TestOutboundComponentEvidenceParity(t *testing.T) {
	for _, fixture := range []string{"javascript/outbound", "typescript/outbound", "python/outbound", "javascript/xss-fetch"} {
		t.Run(fixture, func(t *testing.T) {
			r, err := parse.Analyze("../parse/testdata/"+fixture, "")
			if err != nil {
				t.Fatal(err)
			}
			for i := range r.Uses {
				r.Uses[i] = predecessorNodeUse(r.Uses[i])
				if r.Uses[i].Kind == "outbound_http_candidate" {
					r.Uses[i].Components = nil
				}
			}
			report.Enrich(r)
			b, _ := json.Marshal(r)
			// The v7 catalog changes component provenance and family fact prose.
			// Discovery identities and observation-only outcomes remain unchanged.
			// E4: Node http/https SSRF + path single-pass / Python phase-2 file APIs
			// change discovery report bytes for these fixtures; identities stay stable.
			want := map[string]string{
				"javascript/outbound":  "072a30548c48c7718084ef3b2f0266ae68128191ce20bb33a56af239592a4744",
				"typescript/outbound":  "50ad7e4c4580279dbe41ebd09f8c09e2db52f810c16173735e4a7c59d62244d5",
				"python/outbound":      "24bf5044c43c4801d508936435c4c08fb5087860a3d10f619355fcae767d9e71",
				"javascript/xss-fetch": "73f4032846b5d8ec5fd5e0c1369f12d7471c539ad09668cb82e724b43e4a4fe1",
			}[fixture]
			if got := fmt.Sprintf("%x", sha256.Sum256(b)); got != want {
				t.Fatalf("source/report drift: got %s want %s", got, want)
			}
		})
	}
}

func TestOutboundObservationNotAssessed(t *testing.T) {
	r, err := parse.Analyze("../parse/testdata/javascript/outbound", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{"openai", "jev"} {
		calls := 0
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
		defer s.Close()
		c, _ := New(provider, "fixture-model", "key")
		c.endpoint = s.URL
		found := 0
		for _, u := range r.Uses {
			if u.Kind != "outbound_http_candidate" {
				continue
			}
			found++
			a := c.Assess(context.Background(), u)
			if a.Status != "not_run" || a.Reason != "Outbound security assessment is not implemented; this is an observation only." || a.RequestDigest != "" || a.QuestionVersion != "" {
				t.Errorf("observation assessment: %+v", a)
			}
			a, trace := c.AssessTrace(context.Background(), u)
			if a.Status != "not_run" || len(trace.Request) != 0 || trace.RequestDigest != "" {
				t.Errorf("observation trace: status=%s request bytes=%d", a.Status, trace.RequestBytes)
			}
			preview, err := c.Preview(u)
			if err == nil || len(preview.Request) != 0 || preview.RequestDigest != "" {
				t.Errorf("preview: bytes=%d err=%v", preview.RequestBytes, err)
			}
		}
		if found == 0 || calls != 0 {
			t.Fatalf("found=%d calls=%d", found, calls)
		}
	}
}

func TestOutboundComponentReportParity(t *testing.T) {
	calls := 0
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer stub.Close()
	t.Cleanup(func() {
		if calls != 0 {
			t.Errorf("observation report made %d model calls", calls)
		}
	})
	for _, fixture := range []string{"javascript/outbound", "typescript/outbound", "python/outbound"} {
		r, err := parse.Analyze("../parse/testdata/"+fixture, "")
		if err != nil {
			t.Fatal(err)
		}
		c, _ := New("openai", "fixture-model", "key")
		c.endpoint = stub.URL
		count := 0
		for i := range r.Uses {
			if r.Uses[i].Kind == "outbound_http_candidate" {
				r.Uses[i].Assessment = c.Assess(context.Background(), r.Uses[i])
				count++
			}
		}
		report.Enrich(r)
		data, _ := json.Marshal(r)
		var saved analysis.AnalysisReport
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
		report.Enrich(&saved)
		if len(saved.Entries) != len(r.Entries) || len(saved.Findings) != len(r.Findings) {
			t.Fatal("coverage drift")
		}
		found := 0
		for i, u := range saved.Uses {
			if u.Kind != "outbound_http_candidate" {
				continue
			}
			found++
			if !reflect.DeepEqual(u.Assessment, r.Uses[i].Assessment) || !sameJSON(u.Components, r.Uses[i].Components) || !reflect.DeepEqual(u.Gaps, r.Uses[i].Gaps) || u.Sink != r.Uses[i].Sink {
				t.Fatalf("raw evidence/provenance drift assessment=%v components=%v gaps=%v sink=%v", reflect.DeepEqual(u.Assessment, r.Uses[i].Assessment), reflect.DeepEqual(u.Components, r.Uses[i].Components), reflect.DeepEqual(u.Gaps, r.Uses[i].Gaps), u.Sink == r.Uses[i].Sink)
			}
			if saved.Findings[i].Status != "needs_review" || saved.Findings[i].RecordType != "analysis" {
				t.Fatal("observation upgraded to finding")
			}
		}
		if found != count {
			t.Fatal("outbound count drift")
		}
		var html bytes.Buffer
		if err := report.HTML(&html, &saved); err != nil {
			t.Fatal(err)
		}
		if strings.Count(html.String(), "Outbound request needs destination review") != count {
			t.Fatal("HTML destination count drift")
		}
		run := report.SARIF(&saved)["runs"].([]any)[0].(map[string]any)
		results := run["results"].([]any)
		if len(results) != len(saved.Uses) {
			t.Fatal("SARIF count drift")
		}
		for i, raw := range results {
			props := raw.(map[string]any)["properties"].(map[string]any)
			f := props["scan.finding"].(analysis.Finding)
			if f.Status != saved.Findings[i].Status || props["scan.useId"] != saved.Uses[i].ID {
				t.Fatal("SARIF status/source drift")
			}
		}
	}
}
