package judge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/pipeline"
	"github.com/zazzcode/zazzles/scan/internal/report"
)

func TestGraphQLProtectionContexts(t *testing.T) {
	for _, language := range []string{"javascript", "typescript", "unknown-guard"} {
		t.Run(language, func(t *testing.T) {
			root := "../langjs/testdata/" + language + "/graphql"
			if language == "unknown-guard" {
				root = t.TempDir()
				source := "import {ApolloServer} from '@apollo/server';import {Sequelize} from 'sequelize';const db=new Sequelize('sqlite::memory:');new ApolloServer({typeDefs:`type Query { unknown(email:String):String }`,resolvers:{Query:{unknown:(p,args)=>{guard(args.email);return db.query('SELECT '+args.email)}}}});"
				if err := os.WriteFile(filepath.Join(root, "app.js"), []byte(source), 0600); err != nil {
					t.Fatal(err)
				}
			}
			r, err := pipeline.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				var body struct {
					Input     string `json:"input"`
					Questions []struct {
						Name string `json:"name"`
					} `json:"questions"`
				}
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				if !strings.Contains(body.Input, "graphql_resolver") || !strings.Contains(body.Input, "graphql.args") || !strings.Contains(body.Input, "schema") {
					t.Error("real resolver/input/schema witnesses missing")
				}
				protection := "insufficient"
				injection := "vulnerable"
				// This stub deliberately also claims unknown transforms are protected. Go
				// completeness must reject that answer rather than borrowing sibling safety.
				if strings.Contains(body.Input, `"field":"bound"`) || strings.Contains(body.Input, `"field":"guarded"`) || strings.Contains(body.Input, `"field":"unknown"`) {
					protection = "sufficient"
					injection = "protected"
				}
				choices := map[string]string{"validation": "uncertain", "protection": protection, "injection_protection": injection}
				answers := []map[string]string{}
				for _, q := range body.Questions {
					answers = append(answers, map[string]string{"name": q.Name, "type": "choice", "choice": choices[q.Name]})
				}
				json.NewEncoder(w).Encode(map[string]any{"model": "fixture-model", "answers": answers})
			}))
			defer server.Close()
			client, err := New("openai", "fixture-model", "synthetic-test-key")
			if err != nil {
				t.Fatal(err)
			}
			client.endpoint = server.URL
			client.http = server.Client()
			expected := map[string]string{"raw": "confirmed_vulnerability", "open": "confirmed_vulnerability", "bound": "protected_for_claim", "guarded": "protected_for_claim", "unknown": "needs_evidence", "lookup": "confirmed_vulnerability"}
			if language == "unknown-guard" {
				expected = map[string]string{"unknown": "needs_evidence"}
			}
			seen := map[string]bool{}
			for i := range r.Uses {
				u := &r.Uses[i]
				if u.Kind != "sql_query_candidate" {
					continue
				}
				field := u.EntryFacts.GraphQL.Field
				if field == "guarded" && !graphqlHasGuard(u.InvocationFacts) {
					t.Error("guarded shared sink lacks contextual controls")
				}
				if (field == "raw" || field == "open") && graphqlHasGuard(u.InvocationFacts) {
					t.Error("sibling guard crossed invocation")
				}

				got, trace := client.AssessTrace(context.Background(), *u)
				u.Assessment = got
				if got.Status != "completed" || got.FindingStatus != expected[field] {
					t.Errorf("%s: %+v blockers=%+v", field, got, u.Completeness.Blockers)
				}
				seen[field] = true
				if client.Replay(*u, trace).Status != "completed" {
					t.Fatal("exact replay failed")
				}
				changed := *u
				entry := *u.EntryFacts
				metadata := *entry.GraphQL
				metadata.Field = "different"
				entry.GraphQL = &metadata
				changed.EntryFacts = &entry
				if client.Replay(changed, trace).Status != "failed" {
					t.Fatal("changed coordinate replayed stale answer")
				}
			}
			if len(seen) != len(expected) {
				t.Fatalf("assessed %d SQL controls", len(seen))
			}
			base := t.TempDir()
			if artifacts := os.Getenv("ZAZZ_TEST_GRAPHQL_REPORTS"); artifacts != "" {
				base = filepath.Join(artifacts, language)
			}
			_, err = report.WriteBundle(base, r)
			if err != nil {
				t.Fatal(err)
			}
			report.Enrich(r)
			byUse := map[string]analysis.Finding{}
			for _, f := range r.Findings {
				byUse[f.UseID] = f
			}
			sarif := report.SARIF(r)["runs"].([]any)[0].(map[string]any)
			for _, item := range sarif["results"].([]any) {
				props := item.(map[string]any)["properties"].(map[string]any)
				f := props["scan.finding"].(analysis.Finding)
				if byUse[f.UseID].Status != f.Status {
					t.Fatal("assessed SARIF status parity")
				}
			}
		})
	}
}

func graphqlHasGuard(ctx *analysis.InvocationContext) bool {
	for _, c := range ctx.Controls {
		if c.Evidence.Kind != "invoked_callable" {
			return true
		}
	}
	return false
}
