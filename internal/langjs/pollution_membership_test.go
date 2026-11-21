package langjs

import (
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPollutionMembershipGuard(t *testing.T) {
	const full = "['__proto__', 'constructor', 'prototype']"
	for _, tt := range []struct {
		name, declaration, condition, setup, guard, protection string
		partial                                                bool
	}{
		{"set", "const blocked = new Set(" + full + ");", "blocked.has(key)", "", "deny_list", "guarded", false},
		{"array", "const blocked = " + full + ";", "blocked.includes(key)", "", "deny_list", "guarded", false},
		{"array literal", "", full + ".includes(key)", "", "deny_list", "guarded", false},
		{"partial", "const blocked = new Set(['__proto__']);", "blocked.has(key)", "", "deny_list", "raw", true},
		{"mutated set", "const blocked = new Set(" + full + "); blocked.clear();", "blocked.has(key)", "", "unknown", "unknown", false},
		{"mutated array", "const blocked = " + full + "; blocked[0] = 'other';", "blocked.includes(key)", "", "unknown", "unknown", false},
		{"escaped set", "const blocked = new Set(" + full + "); change(blocked);", "blocked.has(key)", "", "unknown", "unknown", false},
		{"custom set", "const Set = custom(); const blocked = new Set(" + full + ");", "blocked.has(key)", "", "unknown", "unknown", false},
		{"helper", "const blocked = " + full + "; function rejects(k) { return blocked.includes(k); }", "rejects(key)", "", "deny_list", "guarded", false},
		{"local constant", "", "blocked.includes(key)", "const blocked = " + full + ";", "deny_list", "guarded", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
`+tt.declaration+`
function update(target, source) {
  `+tt.setup+`
  for (const key in source) {
    if (`+tt.condition+`) continue;
    if (source[key] && typeof source[key] === 'object') update(target[key], source[key]);
    else target[key] = source[key];
  }
}
app.post('/settings', (req, res) => { update({}, req.body); res.end(); });
`)
			report, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			uses := usesOf(report, analysis.PollutionKind, "server.js")
			if len(uses) != 1 {
				t.Fatalf("pollution records = %d, want 1", len(uses))
			}
			u := uses[0]
			if p := u.Pollution; p.Guard != tt.guard || p.Paths[0].Protection != tt.protection {
				t.Errorf("facts = %+v, want %s, %s", p, tt.guard, tt.protection)
			}
			if incomplete := slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool {
				return g.Kind == "key_guard_incomplete" && strings.Contains(g.Detail, "constructor")
			}); incomplete != tt.partial {
				t.Errorf("incomplete = %t, want %t", incomplete, tt.partial)
			}
		})
	}
}
