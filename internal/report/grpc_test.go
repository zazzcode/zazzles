package report

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/pipeline"
)

func TestGRPCPipeline(t *testing.T) {
	for _, language := range []string{"javascript", "typescript"} {
		t.Run(language, func(t *testing.T) {
			root := "../langjs/testdata/" + language + "/grpc"
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			saved, html, run := dynamicBundle(t, r)
			if saved.SchemaVersion != analysis.ReportSchemaVersion || len(saved.Entries) != 11 {
				t.Fatal("schema/inventory lost")
			}
			for _, e := range saved.Entries {
				if !strings.Contains(html, EntryLabel(e)) || !strings.Contains(html, e.ID) || e.HTTP != nil {
					t.Fatal("gRPC-specific zero-use presentation missing")
				}
			}
			evidence := []analysis.Evidence{}
			for _, reg := range saved.Registrations {
				evidence = append(evidence, reg.Origin)
				evidence = append(evidence, reg.DerivedFrom...)
			}
			for _, u := range saved.Uses {
				evidence = append(evidence, u.Sink)
				evidence = append(evidence, u.Context...)
				for _, d := range u.Dependencies {
					evidence = append(evidence, d.Source)
					evidence = append(evidence, d.Transfers...)
				}
			}
			for _, e := range evidence {
				src, err := os.ReadFile(filepath.Join(root, e.Span.File))
				if err != nil {
					t.Fatal(err)
				}
				if e.SHA256 != fmt.Sprintf("%x", sha256.Sum256(src)) || e.Span.StartByte < 0 || e.Span.EndByte > len(src) || string(src[e.Span.StartByte:e.Span.EndByte]) != e.Text {
					t.Fatalf("source snapshot mismatch: %+v", e)
				}
			}
			sinks := map[string]analysis.Span{}
			for _, u := range saved.Uses {
				sinks[u.ID] = u.Sink.Span
			}
			for _, item := range run["results"].([]any) {
				result := item.(map[string]any)
				props := result["properties"].(map[string]any)
				if props["scan.entryKind"] != "grpc" || props["scan.route"] != nil {
					t.Fatal("fake HTTP SARIF")
				}
				span := sinks[props["scan.useId"].(string)]
				location := result["locations"].([]any)[0].(map[string]any)["physicalLocation"].(map[string]any)
				if location["artifactLocation"].(map[string]string)["uri"] != span.File {
					t.Fatal("primary location is not actual sink")
				}
				related := result["relatedLocations"].([]any)
				schema := false
				for _, rel := range related {
					text := fmt.Sprint(rel)
					schema = schema || strings.Contains(text, "search.proto")
				}
				if !schema {
					t.Fatal("SARIF proto related location missing")
				}
			}
			notifications := fmt.Sprint(run["invocations"])
			if !strings.Contains(notifications, "grpc_handler_unresolved") || !strings.Contains(notifications, "grpc_streaming_unsupported") {
				t.Fatal("zero-use gaps lost")
			}
		})
	}
}
