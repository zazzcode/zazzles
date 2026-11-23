package report

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

type sarifRule struct {
	ID   string `json:"id"`
	Help struct {
		Text string `json:"text"`
	} `json:"help"`
	Properties struct {
		Tags []string `json:"tags"`
	} `json:"properties"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex int    `json:"ruleIndex"`
	Locations []struct {
		PhysicalLocation struct {
			ArtifactLocation struct {
				URI string `json:"uri"`
			} `json:"artifactLocation"`
			Region struct {
				StartLine int `json:"startLine"`
			} `json:"region"`
		} `json:"physicalLocation"`
	} `json:"locations"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Rules []sarifRule `json:"rules"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

func (r sarifRun) Rules() []sarifRule { return r.Tool.Driver.Rules }

type sarifConfiguration struct {
	Runs []sarifRun `json:"runs"`
}

var configurationReportCases = []struct {
	check, cwe, file, help string
	line                   int
}{
	{analysis.CheckDirectoryListing, "CWE-548", "deploy/site.conf", "directory listing", 2},
	{analysis.CheckCSRFDisabled, "CWE-352", "config/packages/framework.yaml", "CSRF token", 4},
	{analysis.CheckSessionCookieScript, "CWE-1004", "config/packages/framework.yaml", "out of scripts", 13},
	{analysis.CheckSessionCookieTransport, "CWE-614", "deploy/php.ini", "only over HTTPS", 7},
	{analysis.CheckDebugEnabled, "CWE-489", "deploy/env.stage", "debug output", 2},
	{analysis.CheckScheduledPrivileged, "CWE-732", "Dockerfile", "less privileged user", 50},
	{analysis.CheckRemoteInclude, "CWE-98", "php.ini", "loading a URL", 5},
}

func confirmedConfiguration() *analysis.AnalysisReport {
	r := &analysis.AnalysisReport{}
	for _, tt := range configurationReportCases {
		span := analysis.Span{File: tt.file, StartLine: tt.line, EndLine: tt.line, StartByte: tt.line * 10, EndByte: tt.line*10 + 8}
		setting := analysis.Evidence{Kind: "setting", Text: "setting " + tt.check, Span: span, SHA256: "h"}
		r.Uses = append(r.Uses, analysis.CandidateUse{
			ID: "use:" + tt.check, EntryID: "entry:1", Kind: analysis.ConfigurationKind, Sink: setting,
			Dependencies: []analysis.Dependency{}, Context: []analysis.Evidence{}, Gaps: []analysis.Gap{},
			Configuration: &analysis.ConfigurationFacts{Check: tt.check, Setting: setting, Value: "x", Joined: []analysis.Evidence{}},
			Assessment: analysis.Assessment{Status: "completed", FindingStatus: "confirmed_vulnerability", Reason: "stubbed", QuestionVersion: analysispacks.ConfigurationProtocol,
				Answers: map[string]string{"setting_effect": "in_effect", "weakness": "weakens", "mitigation": "none"}},
		})
	}
	return r
}

// One stubbed Confirmed candidate of each check reaches the report with the
// insecure-configuration type and a SARIF rule of its own that carries the
// check's CWE and help text, whatever order the checks come in.
func TestConfigurationFindingsReport(t *testing.T) {
	r := confirmedConfiguration()
	slices.Reverse(r.Uses)
	Enrich(r)
	for i, f := range r.Findings {
		if !slices.Equal(f.TypeIDs, []string{"insecure-configuration"}) || f.Status != "confirmed_vulnerability" || f.RecordType != "finding" {
			t.Fatalf("%s: finding %+v", r.Uses[i].Configuration.Check, f)
		}
	}
	if !slices.ContainsFunc(r.FindingTypes, func(ft analysis.FindingType) bool { return ft.ID == "insecure-configuration" }) {
		t.Fatal("finding type not listed")
	}
	raw, err := json.Marshal(SARIF(r))
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifConfiguration
	if err := json.Unmarshal(raw, &sarif); err != nil {
		t.Fatal(err)
	}
	run := sarif.Runs[0]
	if len(run.Rules()) != len(configurationReportCases) || len(run.Results) != len(configurationReportCases) {
		t.Fatalf("%d rules and %d results for %d checks", len(run.Rules()), len(run.Results), len(configurationReportCases))
	}
	for _, tt := range configurationReportCases {
		id := "scan/insecure-configuration/" + tt.check
		res := run.Results[slices.IndexFunc(run.Results, func(x sarifResult) bool { return x.RuleID == id })]
		rule := run.Rules()[res.RuleIndex]
		if rule.ID != id || !slices.Contains(rule.Properties.Tags, tt.cwe) || !strings.Contains(rule.Help.Text, tt.help) {
			t.Errorf("%s: rule %+v, want %s with help about %q", tt.check, rule, tt.cwe, tt.help)
		}
		for _, other := range configurationReportCases {
			if other.cwe != tt.cwe && slices.Contains(rule.Properties.Tags, other.cwe) {
				t.Errorf("%s: rule carries %s of another check", tt.check, other.cwe)
			}
		}
	}
}

// A finding anchored at a Dockerfile, a YAML file or another non-source file
// renders with that file and line in SARIF and HTML.
func TestConfigurationFindingLocations(t *testing.T) {
	r := confirmedConfiguration()
	Enrich(r)
	raw, err := json.Marshal(SARIF(r))
	if err != nil {
		t.Fatal(err)
	}
	var sarif sarifConfiguration
	if err := json.Unmarshal(raw, &sarif); err != nil {
		t.Fatal(err)
	}
	var page bytes.Buffer
	if err := HTML(&page, r); err != nil {
		t.Fatal(err)
	}
	for i, tt := range configurationReportCases {
		loc := sarif.Runs[0].Results[i].Locations
		if len(loc) == 0 || loc[0].PhysicalLocation.ArtifactLocation.URI != tt.file || loc[0].PhysicalLocation.Region.StartLine != tt.line {
			t.Errorf("%s: SARIF location %+v, want %s:%d", tt.check, loc, tt.file, tt.line)
		}
		if !strings.Contains(page.String(), tt.file) {
			t.Errorf("%s: HTML does not name %s", tt.check, tt.file)
		}
	}
}
