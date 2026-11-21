package langpy

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSSRFCandidates(t *testing.T) {
	for _, tt := range []struct {
		name     string
		files    map[string]string
		contract string // empty: stays an observation
	}{
		{"python requests", map[string]string{"app.py": "from flask import Flask, request\nimport requests\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    requests.get(request.args.get('url'))\n    return 'ok'\n"}, "python-http-url-v1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			uses := outboundUses(t, tt.files)
			if len(uses) != 1 {
				t.Fatalf("outbound uses=%d", len(uses))
			}
			u := uses[0]
			if tt.contract == "" {
				if u.Kind != "outbound_http_candidate" {
					t.Fatalf("became %s", u.Kind)
				}
				return
			}
			if u.Kind != "ssrf_candidate" || u.APIModel == nil || u.APIModel.ID != tt.contract || u.Outbound.ContractID != tt.contract {
				t.Fatalf("kind=%s api=%+v outbound=%+v", u.Kind, u.APIModel, u.Outbound)
			}
			if u.Components == nil || u.Components.Failure != "" {
				t.Fatalf("component selection: %+v", u.Components)
			}
			if len(u.Dependencies) == 0 || len(u.Outbound.Paths) != len(u.Dependencies) {
				t.Fatalf("paths=%+v deps=%d", u.Outbound.Paths, len(u.Dependencies))
			}
			for _, d := range u.Dependencies {
				if d.SinkSlot != analysis.OutboundSlotDestination {
					t.Fatalf("dependency slot %q", d.SinkSlot)
				}
			}
			if u.Completeness == nil || u.Completeness.ClaimKind != "ssrf" || len(u.Completeness.Evidence["sink_binding"]) == 0 || len(u.Completeness.Evidence["destination_operand"]) == 0 {
				t.Fatalf("completeness: %+v", u.Completeness)
			}
		})
	}
}

func TestOutboundDestinationOrigin(t *testing.T) {
	t.Run("python second-order destination", func(t *testing.T) {
		uses := outboundUses(t, map[string]string{"app.py": "from flask import Flask, request\nimport requests\napp = Flask(__name__)\n@app.route('/x')\ndef x():\n    r = requests.get('https://api.invalid/next')\n    requests.get(r.text)\n    requests.post('https://api.invalid/fixed', data=request.args.get('v'))\n    return 'ok'\n"})
		if len(uses) != 1 || uses[0].Kind != "outbound_http_candidate" || uses[0].Outbound.DestinationOrigin != analysis.DestinationExternalData {
			t.Fatalf("uses=%+v", uses)
		}
	})
}

func outboundUses(t *testing.T, files map[string]string) []analysis.CandidateUse {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		writeSource(t, root, name, src)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "outbound_http_candidate" || u.Kind == "ssrf_candidate" {
			out = append(out, u)
		}
	}
	return out
}
