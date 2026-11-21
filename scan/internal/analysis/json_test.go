package analysis

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGuidelineMetadataCompatibility(t *testing.T) {
	for _, tt := range []struct {
		name, input, want string
	}{
		{"historical", `{"schema_version":1,"practice":[{"id":"python","version":"2"}],"uses":[]}`, "python"},
		{"current", `{"schema_version":2,"analysis_guidelines":[{"id":"javascript","version":"5"}],"uses":[]}`, "javascript"},
		{"current key wins", `{"schema_version":1,"analysis_guidelines":[{"id":"javascript"}],"practice":[{"id":"python"}],"uses":[]}`, "javascript"},
		{"no metadata", `{"schema_version":1,"uses":[]}`, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var r AnalysisReport
			if err := json.Unmarshal([]byte(tt.input), &r); err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if len(r.AnalysisGuidelines) != 0 {
					t.Fatal("invented guidelines")
				}
			} else if len(r.AnalysisGuidelines) != 1 || r.AnalysisGuidelines[0].ID != tt.want {
				t.Fatalf("guidelines=%+v", r.AnalysisGuidelines)
			}
			encoded, err := json.Marshal(r)
			if err != nil || strings.Contains(string(encoded), `"practice":`) {
				t.Fatalf("obsolete metadata emitted: %s, %v", encoded, err)
			}
			if tt.want != "" && !strings.Contains(string(encoded), `"analysis_guidelines":`) {
				t.Fatal("guideline metadata lost during round trip")
			}
		})
	}
}
