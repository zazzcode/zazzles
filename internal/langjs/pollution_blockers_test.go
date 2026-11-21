package langjs

import (
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func TestPollutionWriteHelperBlockers(t *testing.T) {
	for _, tt := range []struct {
		name, setup, before, after string
		blockers                   int
	}{
		{name: "global logger", before: "console.log(req.body);"},
		{name: "shadowed console", setup: "const console = createValidator();", before: "console.log(req.body);", blockers: 1},
		{name: "verified logger", setup: "import pino from 'pino'; const logger = pino();", before: "logger.info(req.body);"},
		{name: "unresolved before", before: "validate(req.body);", blockers: 1},
		{name: "unresolved after", after: "notify(req.body);"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.js", `const express = require('express');
const app = express();
app.use(express.json());
const store = {};
function save(target, path, value) {
  let cursor = target;
  const parts = path.split('.');
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}
`+tt.setup+`
app.post('/settings', (req, res) => {
  `+tt.before+`
  save(store, req.body.path, req.body.value);
  `+tt.after+`
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
			blockers := uses[0].Completeness.Blockers
			if len(blockers) != tt.blockers || len(blockers) > 0 && blockers[0].Kind != "input_helper_unresolved" {
				t.Fatalf("blockers = %+v, want %d unresolved helper blockers", blockers, tt.blockers)
			}
		})
	}
}
