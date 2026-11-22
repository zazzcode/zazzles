package langphp

import (
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

func TestSymfonyServices(t *testing.T) {
	report, err := Analyze("testdata/symfony/services-ops", "")
	if err != nil {
		t.Fatal(err)
	}
	const controller = "src/Controller/Ops.php"
	const service = "src/Reader.php"
	const command = "command_execution_candidate"
	const ssrf = "ssrf_candidate"
	const outbound = "outbound_http_candidate"
	const localPath = "path_traversal_candidate"
	names := map[string]string{}
	for _, entry := range report.Entries {
		names[entry.ID] = entry.Name
	}
	for _, tc := range []struct {
		id, entry, file, kind, contract string
		line                            int
		check                           func(*testing.T, analysis.CandidateUse)
	}{
		{"SV-01", "ANY /audit", service, command, "php-program-execution-v1", 16, func(t *testing.T, use analysis.CandidateUse) {
			if use.Command == nil || use.Command.EffectiveShellMode != "enabled" || use.Command.Operands[0].Slot != analysis.CommandSlotShell {
				t.Fatalf("shell operand: %+v", use.Command)
			}
			if !slices.ContainsFunc(use.InputFacts.Values, func(v analysis.InputValueFact) bool { return v.Origin == "http.headers" }) {
				t.Fatalf("header source missing: %+v", use.InputFacts)
			}
			if !slices.ContainsFunc(use.Context, func(e analysis.Evidence) bool { return e.Kind == "configuration_precondition" }) {
				t.Fatal("configuration precondition missing")
			}
			if !slices.ContainsFunc(analysispacks.GuardContracts(use), func(g analysispacks.GuardContract) bool {
				return g.Guard == "filter_validate_url" && g.At == "src/Reader.php:29"
			}) {
				t.Fatalf("helper guard contract missing: %+v", analysispacks.GuardContracts(use))
			}
		}},
		{"SV-02", "ANY /quote", service, command, "php-program-execution-v1", 23, func(t *testing.T, use analysis.CandidateUse) {
			if !slices.ContainsFunc(use.Command.Paths, func(p analysis.CommandPath) bool {
				return p.Protection == "guarded" && strings.Contains(p.Reason, "escapeshellarg")
			}) {
				t.Fatalf("quoted shell path missing: %+v", use.Command)
			}
		}},
		{"SV-03", "ANY /shell", controller, command, "symfony-process-v1", 26, func(t *testing.T, use analysis.CandidateUse) {
			if use.Command.EffectiveShellMode != "enabled" || use.Command.Operands[0].Slot != analysis.CommandSlotShell {
				t.Fatalf("shell operand missing: %+v", use.Command)
			}
		}},
		{"SV-04/argv", "ANY /argv", controller, command, "symfony-process-v1", 31, func(t *testing.T, use analysis.CandidateUse) {
			if use.Command.EffectiveShellMode != "disabled" || !slices.ContainsFunc(use.Command.Paths, func(p analysis.CommandPath) bool {
				return p.Operand == "argument:1"
			}) {
				t.Fatalf("argv operand missing: %+v", use.Command)
			}
		}},
		{"SV-04/literal", "ANY /argv", controller, "", "", 32, nil},
		{"SV-05", "ANY /use/{record}", controller, command, "php-program-execution-v1", 37, func(t *testing.T, use analysis.CandidateUse) {
			if !slices.ContainsFunc(use.Dependencies, func(d analysis.Dependency) bool {
				return d.StorageKey == "php-sql:record.suffix" && d.Source.Kind == "input_source"
			}) {
				t.Fatalf("request writer missing: %+v", use.Dependencies)
			}
		}},
		{"SV-06/ssrf", "ANY /remote", service, ssrf, "php-url-open-v1", 26, symfonyRequestDestination},
		{"SV-06/path", "ANY /remote", service, localPath, "php-filesystem-v1", 26, nil},
		{"SV-07", "ANY /prefix/{id}", controller, ssrf, "php-url-open-v1", 52, func(t *testing.T, use analysis.CandidateUse) {
			symfonyRequestDestination(t, use)
			if !slices.ContainsFunc(use.Context, func(e analysis.Evidence) bool {
				return e.Kind == "destination_prefix" && strings.Contains(e.Text, "https://api.example.test/v1/")
			}) {
				t.Fatal("fixed destination prefix missing")
			}
		}},
		{"SV-07/no-path", "ANY /prefix/{id}", controller, "!path_traversal_candidate", "", 52, nil},
		{"SV-08", "ANY /status", controller, "", "", 57, nil},
		{"SV-09", "ANY /client", controller, ssrf, "symfony-http-client-v1", 62, symfonyRequestDestination},
		{"SV-10", "ANY /curl", controller, ssrf, "php-url-open-v1", 68, symfonyRequestDestination},
		{"SV-10/options", "ANY /curl/options", controller, ssrf, "php-url-open-v1", 85, func(t *testing.T, use analysis.CandidateUse) {
			symfonyRequestDestination(t, use)
			if len(use.Dependencies) != 1 || !strings.Contains(use.Dependencies[0].Source.Text, "get('selected')") {
				t.Fatalf("cURL destination should use only CURLOPT_URL: %+v", use.Dependencies)
			}
		}},
		{"SV-10/string-key", "ANY /curl/options", controller, "!ssrf_candidate", "", 86, nil},
		{"SV-10/initial", "ANY /curl/options", controller, ssrf, "php-url-open-v1", 87, symfonyRequestDestination},
		{"SV-11", "ANY /feed/{record}", controller, outbound, "php-url-open-v1", 73, func(t *testing.T, use analysis.CandidateUse) {
			if use.Outbound == nil || use.Outbound.DestinationOrigin != analysis.DestinationExternalData {
				t.Fatalf("stored outbound origin missing: %+v", use.Outbound)
			}
		}},
		{"SV-12/read", "ANY /local", controller, localPath, "php-filesystem-v1", 78, nil},
		{"SV-12/no-ssrf", "ANY /local", controller, "!ssrf_candidate", "", 78, nil},
		{"SV-12/response", "ANY /local", controller, localPath, "symfony-file-response-v1", 79, nil},
		{"SV-05/stored-path", "ANY /remove/{record}", controller, localPath, "php-filesystem-v1", 92, func(t *testing.T, use analysis.CandidateUse) {
			operand := use.Path.Operands[0]
			if len(operand.Context) == 0 || use.Context[operand.Context[0]].Kind != "path_operand" ||
				!strings.Contains(use.Context[operand.Context[0]].Text, "/records/") {
				t.Fatalf("path slot does not point to its source operand: %+v", operand)
			}
			for _, flow := range use.Path.Paths {
				if flow.Root != "/src/Controller/records" || !slices.Contains(flow.Transforms, analysis.PathTransformConcat) {
					t.Fatalf("stored path loses its base or construction: %+v", flow)
				}
			}
		}},
		{"SV-06/presence", "ANY /optional-destination", controller, ssrf, "php-url-open-v1", 101, func(t *testing.T, use analysis.CandidateUse) {
			symfonyRequestDestination(t, use)
			for _, p := range use.Outbound.Paths {
				if p.Protection != "raw" || len(p.Controls) != 0 {
					t.Fatalf("presence test changes destination protection: %+v", p)
				}
			}
		}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			found := false
			absent := tc.kind == "" || strings.HasPrefix(tc.kind, "!")
			for _, use := range report.Uses {
				at := use.Sink.Span
				if names[use.EntryID] != tc.entry || at.File != tc.file || at.StartLine != tc.line {
					continue
				}
				if tc.kind != "" && use.Kind != strings.TrimPrefix(tc.kind, "!") {
					continue
				}
				if absent {
					t.Fatalf("unexpected %s candidate", use.Kind)
				}
				found = true
				if use.APIModel == nil || use.APIModel.ID != tc.contract {
					t.Fatalf("contract %+v, want %s", use.APIModel, tc.contract)
				}
				if _, err := analysispacks.Select(use); err != nil {
					t.Fatalf("component selection: %v", err)
				}
				if tc.check != nil {
					tc.check(t, use)
				}
			}
			if !found && !absent {
				t.Fatalf("missing %s at %s:%d under %s", tc.kind, tc.file, tc.line, tc.entry)
			}
		})
	}
}

func symfonyRequestDestination(t *testing.T, use analysis.CandidateUse) {
	t.Helper()
	if use.Outbound == nil || use.Outbound.DestinationOrigin != analysis.DestinationRequest || len(use.Outbound.Paths) == 0 {
		t.Fatalf("request destination missing: %+v", use.Outbound)
	}
}
