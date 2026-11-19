package judge

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/pipeline"
)

// TestDVWARequestSizes (close-findings-gaps D-13, AC5) plans every DVWA
// request offline. A record over the request limit is planned in path
// groups: every group request it sends is under the limit and names its
// withheld paths. Remaining over-limit records are listed with their
// smallest group. It needs ZAZZLES_DVWA and never sends a request.
func TestDVWARequestSizes(t *testing.T) {
	root := os.Getenv("ZAZZLES_DVWA")
	if root == "" {
		t.Skip("set ZAZZLES_DVWA to a clean DVWA checkout")
	}
	r, err := pipeline.Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	c, err := New("openai", "fixture-model", "synthetic-test-key")
	if err != nil {
		t.Fatal(err)
	}
	entries := map[string]string{}
	for _, e := range r.Entries {
		entries[e.ID] = e.Location.Span.File
	}
	var lines []string
	over, grouped, remaining, requests := 0, 0, 0, 0
	for _, u := range r.Uses {
		if u.Kind == "xss_data_candidate" || u.Kind == "outbound_http_candidate" {
			continue
		}
		full, _, err := c.budgetedPayload(u)
		if err != nil || len(full) <= requestLimit {
			continue
		}
		over++
		trace, _ := c.Preview(u)
		groups, _ := c.planPathGroups(u)
		head := fmt.Sprintf("%s %s:%d entry=%s whole=%d groups=%d", u.Kind, u.Sink.Span.File, u.Sink.Span.StartLine, entries[u.EntryID], len(full), len(groups))
		if len(trace.Groups) == 0 {
			remaining++
			lines = append(lines, head+" NOT GROUPED (evidence_too_large)")
			continue
		}
		grouped++
		fits := 0
		for i, g := range trace.Groups {
			fit := g.RequestBytes <= requestLimit
			if fit {
				fits++
				requests++
				if !strings.Contains(string(g.Request), "path_group_omitted") || !strings.Contains(string(g.Request), "withheld") {
					t.Errorf("%s group %d does not name its withheld paths", head, i)
				}
			}
			lines = append(lines, fmt.Sprintf("    group %d %s: deps=%d bytes=%d fits=%v", i, groups[i].key, len(groups[i].deps), g.RequestBytes, fit))
		}
		for i := maxPathGroups; i < len(groups); i++ {
			lines = append(lines, fmt.Sprintf("    group %d %s: deps=%d not judged (%s)", i, groups[i].key, len(groups[i].deps), pathGroupCap))
		}
		if fits == 0 {
			remaining++
			head += fmt.Sprintf(" REMAINS evidence_too_large (smallest group %d bytes)", trace.RequestBytes)
		}
		lines = append(lines, head)
	}
	t.Logf("over the %d-byte limit: %d records; grouped %d; still evidence_too_large %d; group requests %d\n%s", requestLimit, over, grouped, remaining, requests, strings.Join(lines, "\n"))
	if remaining > 0 {
		t.Errorf("%d DVWA records remain evidence_too_large", remaining)
	}
}
