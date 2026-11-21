package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestPollutionMapGate(t *testing.T) {
	for _, tt := range []struct {
		name, setup, gate, guard, protection string
	}{
		{"closed map", "const known = new Map([['settings', true]]);",
			"if (!known.has(key)) return;", "map_membership", "guarded"},
		{"map key set contains a prototype name", "const known = new Map([['constructor', true]]);",
			"if (!known.has(key)) return;", "map_membership", "unknown"},
		{"mutated map", "const known = new Map([['settings', true]]); initialize(known);",
			"if (!known.has(key)) return;", "map_membership", "unknown"},
		{"custom has", "const known = { has: permits };",
			"if (!known.has(key)) return;", "unknown", "unknown"},
		{"lookup result through lazy factory", `let cache = null;
function getMap() {
  if (cache === null) {
    cache = new Map();
    cache.set(loadKey(), 'settings');
  }
  return cache;
}
function find(key) {
  const rows = getMap();
  if (rows.has(key)) { return rows.get(key) ?? null; }
  return null;
}`, "let row; try { row = find(key); if (row == null) return; } catch (error) { return; }", "map_membership", "unknown"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
const store = {};
`+tt.setup+`
app.post('/settings', (req, res) => {
  const key = req.body.key;
  `+tt.gate+`
  store[key][req.body.field] = req.body.value;
  res.end();
});
`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != 1 {
				t.Fatalf("pollution records = %d, want 1", len(uses))
			}
			if tt.protection == "guarded" && len(uses[0].Completeness.Blockers) != 0 {
				t.Errorf("complete membership proof has blockers: %+v", uses[0].Completeness.Blockers)
			}
			if p := uses[0].Pollution; p.Guard != tt.guard || p.Paths[0].Protection != tt.protection {
				t.Errorf("facts = %+v, want %s, %s", p, tt.guard, tt.protection)
			}
		})
	}
}

func TestPollutionMapGateDoesNotProtectShadowedKey(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
const known = new Map([['settings', true]]);
const store = {};
app.post('/settings', (req, res) => {
  const key = req.body.selection;
  if (!known.has(key)) return;
  {
    const key = req.body.key;
    store[key][req.body.field] = req.body.value;
  }
  res.end();
});
`)
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := usesOf(report, analysis.PollutionKind, "server.js")
	if len(uses) != 1 {
		t.Fatalf("pollution records = %d, want 1", len(uses))
	}
	if p := uses[0].Pollution; len(p.Blocked) != 0 || p.Paths[0].Protection == "guarded" {
		t.Errorf("a check of the outer key protects the shadowed key: %+v", p)
	}
}
