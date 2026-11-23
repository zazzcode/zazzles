package langphp

import (
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestAuthorizationPeerOrder(t *testing.T) {
	change := analysis.StateChange{Operation: "update", StorageKey: "account.name"}
	set := phpSet{authzChanges: []authzChange{
		{entryID: "writer-b", change: change},
		{entryID: "writer-a", change: change},
	}}
	r := &analysis.AnalysisReport{
		Entries: []analysis.EntryPoint{
			{ID: "writer-b", Name: "POST /account", Access: &analysis.EntryAccess{Authentication: analysis.AccessNone}},
			{ID: "writer-a", Name: "POST /account", Access: &analysis.EntryAccess{Authentication: analysis.AccessRequired}},
		},
		Uses: []analysis.CandidateUse{
			{EntryID: "subject", Authorization: &analysis.AuthorizationFacts{Operation: change}},
			{EntryID: "writer-a", Authorization: &analysis.AuthorizationFacts{Operation: change, Guards: []analysis.AuthorizationGuard{{Kind: analysis.GuardOwnership}}}},
			{EntryID: "writer-a", Authorization: &analysis.AuthorizationFacts{Operation: change, Guards: []analysis.AuthorizationGuard{{Kind: analysis.GuardOwnership}, {Kind: analysis.GuardRole}}}},
		},
	}
	for range 64 {
		set.finishAuthorization(r)
		peers := r.Uses[0].Authorization.PeerAccess
		if len(peers) != 2 || peers[0].Access.Authentication != analysis.AccessRequired || peers[1].Access.Authentication != analysis.AccessNone ||
			!slices.Equal(peers[0].GuardKinds, []string{analysis.GuardOwnership, analysis.GuardRole}) || len(peers[1].GuardKinds) != 0 {
			t.Fatalf("peers not ordered by name then ID, or guard kinds not deduplicated: %+v", peers)
		}
	}
}

func TestAuthorizationGuards(t *testing.T) {
	report := phpAnalyze(t, "testdata/symfony/authorization", "")
	cases := []struct {
		entry, kind, form, source string
		literals                  int
		gap                       string
		classes                   []string
		none                      bool
	}{
		{"POST /item/{item}/gd01", analysis.GuardOwnership, "", "", 0, "", nil, false},
		{"POST /item/{item}/gd02", analysis.GuardOwnership, "", "", 0, "", nil, false},
		{"POST /item/{item}/gd03", analysis.GuardOwnership, "", "", 0, "", nil, false},
		{"POST /item/gd04", analysis.GuardOwnership, "query_scope", "", 0, "", nil, false},
		{"POST /item/{item}/gd05", analysis.GuardRole, "", "", 0, "", nil, false},
		{"POST /item/{item}/gd06", analysis.GuardAuthenticated, "", "", 0, "", nil, false},
		{"POST /item/{account}/gd07/{code}", analysis.GuardSecret, "", "", 0, "", nil, false},
		{"POST /item/{account}/gd08", analysis.GuardAddress, "", analysis.AddressFrameworkIP, 2, "address_trust_configuration_unread", []string{"loopback", "loopback"}, false},
		{"POST /item/{account}/gd09", analysis.GuardAddress, "", analysis.AddressFrameworkIP, 2, "address_trust_configuration_unread", []string{"loopback", "loopback"}, false},
		{"POST /item/{account}/gd10", analysis.GuardAddress, "", analysis.AddressForwardedHeader, 1, "", []string{"private"}, false},
		{"POST /item/{item}/gd11", "", "", "", 0, "", nil, true},
		{"POST /item/{item}/gd12", analysis.GuardUnclassified, "", "", 0, "guard_unclassified", nil, false},
	}
	for _, tt := range cases {
		t.Run(tt.entry, func(t *testing.T) {
			uses := authzUses(report, tt.entry)
			if tt.none {
				if len(uses) == 0 {
					t.Fatal("expected a candidate with no guard")
				}
				if len(uses[0].Authorization.Guards) != 0 {
					t.Fatalf("guards %+v, want none", uses[0].Authorization.Guards)
				}
				return
			}
			if len(uses) == 0 {
				t.Fatalf("no candidate; entries %s", authzSummary(report))
			}
			g := guardOf(uses[0], tt.kind)
			if g == nil {
				t.Fatalf("guards %+v, want %s", uses[0].Authorization.Guards, tt.kind)
			}
			if tt.form != "" && g.Form != tt.form {
				t.Fatalf("form %s", g.Form)
			}
			if tt.source != "" && g.AddressSource != tt.source {
				t.Fatalf("source %s", g.AddressSource)
			}
			if tt.literals > 0 && len(g.Literals) != tt.literals {
				t.Fatalf("literals %v", g.Literals)
			}
			if strings.Join(g.LiteralClass, ",") != strings.Join(tt.classes, ",") && tt.classes != nil {
				t.Fatalf("classes %v", g.LiteralClass)
			}
			if tt.gap != "" && !hasGap(g.Gaps, tt.gap) {
				t.Fatalf("gaps %+v", g.Gaps)
			}
		})
	}
}

func TestAuthorizationCandidates(t *testing.T) {
	report := phpAnalyze(t, "testdata/symfony/authorization", "")
	rename := oneAuthz(t, report, "POST /item/{item}/rename")
	if !hasFacet(rename, analysis.FacetObjectLevel) || rename.Authorization.SubjectProvenance != analysis.SubjectRequestSelected || len(rename.Authorization.Guards) != 0 {
		t.Fatalf("rename %+v", rename.Authorization)
	}
	if accessEntry(t, report, "POST /item/{item}/rename").Access.Authentication != analysis.AccessRequired {
		t.Fatal("rename access")
	}
	owned := oneAuthz(t, report, "POST /item/{item}/gd01")
	if guardOf(owned, analysis.GuardOwnership) == nil {
		t.Fatal("az02")
	}
	if len(authzUses(report, "POST /item/self/rename")) != 0 {
		t.Fatal("current user wrote a candidate")
	}
	removed := oneAuthz(t, report, "POST /item/{item}/remove")
	if removed.Authorization.Operation.Operation != "delete" {
		t.Fatalf("delete %+v", removed.Authorization.Operation)
	}
	found := oneAuthz(t, report, "POST /item/by-id")
	if found.Authorization.SubjectProvenance != analysis.SubjectRequestSelected {
		t.Fatalf("find %+v", found.Authorization)
	}
	file := oneAuthz(t, report, "POST /item/{item}/file")
	if file.Authorization.Operation.Operation != "file_delete" {
		t.Fatalf("file %+v", file.Authorization.Operation)
	}
	grants := oneAuthz(t, report, "POST /portal/account/{account}/grants")
	if !hasFacet(grants, analysis.FacetFunctionLevel) || !hasFacet(grants, analysis.FacetObjectLevel) {
		t.Fatalf("facets %v", grants.Authorization.Facets)
	}
	if len(grants.Authorization.SecurityFields) == 0 || !strings.Contains(strings.Join(grants.Authorization.SecurityFields[0].Roles, ","), "role_source") {
		t.Fatalf("fields %+v", grants.Authorization.SecurityFields)
	}
	if !peerHasRole(report, grants, "ROLE_STAFF") {
		t.Fatalf("peers %+v", grants.Authorization.PeerAccess)
	}
	if len(authzUses(report, "POST /open/literal")) != 0 {
		t.Fatal("literal create")
	}
	created := oneAuthz(t, report, "POST /open/created")
	if !hasFacet(created, analysis.FacetFunctionLevel) || created.Authorization.SubjectProvenance != analysis.SubjectCreated {
		t.Fatalf("created %+v", created.Authorization)
	}
	if len(authzUses(report, "POST /open/comment")) != 0 {
		t.Fatal("comment")
	}
	archive := oneAuthz(t, report, "GET /item/{item}/archive")
	if archive.Authorization.MethodSafe != "yes" {
		t.Fatalf("method_safe %s", archive.Authorization.MethodSafe)
	}
	mails := oneAuthz(t, report, "GET /open/mails")
	if !hasFacet(mails, analysis.FacetDataExposure) || mails.Authorization.SubjectProvenance != analysis.SubjectEnumerated {
		t.Fatalf("mails %+v", mails.Authorization)
	}
	if len(authzUses(report, "GET /open/titles")) != 0 {
		t.Fatal("titles")
	}
	mail := oneAuthz(t, report, "GET /item/{account}/mail")
	if !strings.HasSuffix(mail.Sink.Span.File, ".twig") || !hasFacet(mail, analysis.FacetDataExposure) {
		t.Fatalf("template %+v %s", mail.Authorization, mail.Sink.Span.File)
	}
	if len(authzUses(report, "GET /item/{post}/title")) != 0 {
		t.Fatal("post title")
	}
	if len(authzUses(report, "POST /item/{item}/bag")) != 0 {
		t.Fatal("dynamic write")
	}
	if !hasKind(report, "POST /item/{item}/bag", "mass_assignment_candidate") {
		t.Fatal("mass assignment missing")
	}
	if len(authzUses(report, "GET /item/{item}/peek")) != 0 {
		t.Fatal("peek")
	}
}

func TestAuthorizationTransfer(t *testing.T) {
	report := phpAnalyze(t, "testdata/symfony/authorization-transfer", "")
	held := oneAuthz(t, report, "POST /portal/member/{member}/held")
	if guardOf(held, analysis.GuardOwnership) == nil {
		t.Fatalf("held %+v", held.Authorization.Guards)
	}
	open := oneAuthz(t, report, "POST /portal/member/{member}/open")
	if len(open.Authorization.Guards) != 0 {
		t.Fatalf("open guards %+v", open.Authorization.Guards)
	}
	grants := oneAuthz(t, report, "POST /portal/member/{member}/grants")
	if !peerHasRole(report, grants, "ROLE_STAFF") {
		t.Fatalf("peers %+v", grants.Authorization.PeerAccess)
	}
}

func TestAuthorizationPlain(t *testing.T) {
	report := phpAnalyze(t, "testdata/authorization-plain", "")
	var guarded, session, open []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Kind != analysis.AuthorizationKind {
			continue
		}
		switch {
		case strings.HasSuffix(u.Sink.Span.File, "guarded.php"):
			guarded = append(guarded, u)
		case strings.HasSuffix(u.Sink.Span.File, "session.php"):
			session = append(session, u)
		case strings.HasSuffix(u.Sink.Span.File, "open.php"):
			open = append(open, u)
		}
	}
	if len(guarded) != 1 || guardOf(guarded[0], analysis.GuardAddress) == nil || guarded[0].Authorization.Guards[0].AddressSource != analysis.AddressPeer {
		t.Fatalf("guarded %+v", guarded)
	}
	if len(session) != 0 || len(open) != 0 {
		t.Fatalf("session %d open %d", len(session), len(open))
	}
}

func authzUses(r *analysis.AnalysisReport, entry string) []analysis.CandidateUse {
	id := ""
	for _, e := range r.Entries {
		if e.Name == entry {
			id = e.ID
		}
	}
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == analysis.AuthorizationKind && u.EntryID == id {
			out = append(out, u)
		}
	}
	return out
}

func oneAuthz(t *testing.T, r *analysis.AnalysisReport, entry string) analysis.CandidateUse {
	t.Helper()
	uses := authzUses(r, entry)
	if len(uses) == 0 {
		t.Fatalf("no candidate on %s\n%s", entry, authzSummary(r))
	}
	return uses[0]
}

func guardOf(u analysis.CandidateUse, kind string) *analysis.AuthorizationGuard {
	if u.Authorization == nil {
		return nil
	}
	for i := range u.Authorization.Guards {
		if u.Authorization.Guards[i].Kind == kind {
			return &u.Authorization.Guards[i]
		}
	}
	return nil
}

func hasFacet(u analysis.CandidateUse, facet string) bool {
	return u.Authorization != nil && strings.Contains(strings.Join(u.Authorization.Facets, ","), facet)
}

func peerHasRole(r *analysis.AnalysisReport, u analysis.CandidateUse, role string) bool {
	if u.Authorization == nil {
		return false
	}
	for _, p := range u.Authorization.PeerAccess {
		for _, have := range p.Access.Roles {
			if have == role {
				return true
			}
		}
	}
	return false
}

func hasKind(r *analysis.AnalysisReport, entry, kind string) bool {
	id := ""
	for _, e := range r.Entries {
		if e.Name == entry {
			id = e.ID
		}
	}
	for _, u := range r.Uses {
		if u.EntryID == id && u.Kind == kind {
			return true
		}
	}
	return false
}

func TestSSRFRequestUnchanged(t *testing.T) {
	report := phpAnalyze(t, "testdata/symfony/authorization", "")
	authz := oneAuthz(t, report, "POST /open/fetch/{account}")
	if guardOf(authz, analysis.GuardAddress) == nil {
		t.Fatal("fetch write has no address check")
	}
	linked := map[string]bool{}
	for _, id := range authz.Authorization.ServerSideRequests {
		linked[id] = true
	}
	if len(linked) == 0 {
		t.Fatal("address-guarded write lists no server-side request")
	}
	seen := 0
	for _, u := range report.Uses {
		if u.Kind != "ssrf_candidate" || !linked[u.ID] {
			continue
		}
		seen++
		if u.Authorization != nil {
			t.Fatal("ssrf use carries authorization facts")
		}
	}
	if seen != len(linked) {
		t.Fatalf("server_side_requests %v are not ssrf uses", authz.Authorization.ServerSideRequests)
	}
}

func authzSummary(r *analysis.AnalysisReport) string {
	var b strings.Builder
	for _, e := range r.Entries {
		n := 0
		for _, u := range r.Uses {
			if u.EntryID == e.ID && u.Kind == analysis.AuthorizationKind {
				n++
			}
		}
		if n > 0 {
			b.WriteString(e.Name + "\n")
		}
	}
	return b.String()
}

// A plain-PHP UPDATE or DELETE whose WHERE clause selects the row by a
// request value is an object-level candidate; guards are facts, not filters.
func TestAuthorizationPlainSelected(t *testing.T) {
	report := phpAnalyze(t, "testdata/authorization-plain", "")
	byFile := map[string][]analysis.CandidateUse{}
	for _, u := range report.Uses {
		if u.Kind == analysis.AuthorizationKind {
			byFile[u.Sink.Span.File] = append(byFile[u.Sink.Span.File], u)
		}
	}
	for _, tt := range []struct {
		id, file, operation, class string
		line                       int
		guard, form                string
	}{
		{"AZ-26", "selected.php", "update", "table:members", 5, "", ""},
		{"AZ-27", "selected_signed.php", "update", "table:members", 7, analysis.GuardAuthenticated, ""},
		{"AZ-29", "removed.php", "delete", "table:notes", 3, analysis.GuardOwnership, "query_scope"},
	} {
		t.Run(tt.id, func(t *testing.T) {
			uses := byFile[tt.file]
			if len(uses) != 1 {
				t.Fatalf("%d candidates in %s", len(uses), tt.file)
			}
			u, f := uses[0], uses[0].Authorization
			if err := f.Validate(); err != nil {
				t.Fatal(err)
			}
			if u.Sink.Span.StartLine != tt.line || f.Operation.Operation != tt.operation || f.SubjectClass != tt.class || f.SubjectProvenance != analysis.SubjectRequestSelected {
				t.Fatalf("line %d facts %+v", u.Sink.Span.StartLine, f)
			}
			if len(f.Facets) != 1 || f.Facets[0] != analysis.FacetObjectLevel {
				t.Fatalf("facets %v", f.Facets)
			}
			if len(u.Dependencies) == 0 || u.Dependencies[0].Source.Kind != "input_source" {
				t.Fatalf("selecting sources %+v", u.Dependencies)
			}
			if tt.guard == "" {
				if len(f.Guards) != 0 {
					t.Fatalf("guards %+v", f.Guards)
				}
				return
			}
			if len(f.Guards) != 1 || f.Guards[0].Kind != tt.guard || f.Guards[0].Form != tt.form {
				t.Fatalf("guards %+v", f.Guards)
			}
		})
	}
	t.Run("AZ-28", func(t *testing.T) {
		if n := len(byFile["own.php"]); n != 0 {
			t.Fatalf("%d candidates for a session-selected row", n)
		}
	})
}

// AZ-30: a recovery page that updates the row a submitted address selects is
// recorded like any other request-selected row. The model judges it.
func TestAuthorizationPlainAnonymousFlow(t *testing.T) {
	report := phpAnalyze(t, "testdata/account-plain", "")
	var got []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Kind == analysis.AuthorizationKind {
			got = append(got, u)
		}
	}
	if len(got) != 1 || got[0].Sink.Span.File != "forgot.php" || got[0].Sink.Span.StartLine != 7 || len(got[0].Authorization.Guards) != 0 {
		t.Fatalf("candidates %+v", got)
	}
}
