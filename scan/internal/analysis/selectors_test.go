package analysis

import "testing"

func TestEntrySelectors(t *testing.T) {
	for _, tc := range []struct {
		entry    EntryPoint
		selector EntrySelector
	}{
		{EntryPoint{ID: "gql", Kind: "graphql", GraphQL: &GraphQLEntryMetadata{Type: "Mutation", Field: "create"}}, EntrySelector{Kind: "graphql", Type: "Mutation", Field: "create"}},
		{EntryPoint{ID: "grpc", Kind: "grpc", GRPC: &GRPCEntryMetadata{Package: "accounts", Service: "AccountService", Method: "Create"}}, EntrySelector{Kind: "grpc", Service: "accounts.AccountService", Method: "Create"}},
		{EntryPoint{ID: "browser", Kind: "browser", Name: "Signup", Browser: &BrowserEntryMetadata{Category: "component", Event: "submit"}}, EntrySelector{Kind: "browser", Category: "component", Name: "Signup", Event: "submit"}},
	} {
		t.Run(tc.entry.Kind, func(t *testing.T) {
			if err := tc.selector.Validate(); err != nil {
				t.Fatal(err)
			}
			if !tc.selector.Matches(tc.entry) {
				t.Fatal("typed identity failed")
			}
			r := &AnalysisReport{Entries: []EntryPoint{tc.entry}, InvocationContexts: []InvocationContext{{ID: "a", EntryID: tc.entry.ID, DispatchBindingID: "ba"}, {ID: "b", EntryID: tc.entry.ID, DispatchBindingID: "bb"}}, DispatchBindings: []DispatchBinding{{ID: "ba", EntryID: tc.entry.ID, RegistrationID: "ra"}, {ID: "bb", EntryID: tc.entry.ID, RegistrationID: "rb"}}, Registrations: []EntryRegistration{{ID: "ra", Origin: Evidence{Span: Span{File: "a.ts"}}}, {ID: "rb", Origin: Evidence{Span: Span{File: "b.ts"}}}}}
			r.RecordCheckMatches([]Check{{ID: "check", Selector: &tc.selector}})
			if len(r.CheckMatches) != 2 {
				t.Fatal("lost matched context")
			}
			tc.selector.RegistrationFile = "a.ts"
			r.RecordCheckMatches([]Check{{ID: "check", Selector: &tc.selector}})
			if len(r.CheckMatches) != 1 || r.CheckMatches[0].InvocationContextID != "a" {
				t.Fatal("registration ownership crossed context")
			}
			wrong := tc.entry
			wrong.Kind = "http"
			if tc.selector.Matches(wrong) {
				t.Fatal("kind confused with transport")
			}
		})
	}
}
