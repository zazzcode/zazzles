package pipeline

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/judge"
)

const symfonySamplePin = "086f81f941501bd1170b249e01107ba99beb2962"

func TestSymfonyFixturesSelect(t *testing.T) {
	root := filepath.Join("..", "langphp", "testdata", "symfony")
	dirs, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, dir := range dirs {
		if !dir.IsDir() {
			continue
		}
		t.Run(dir.Name(), func(t *testing.T) {
			report := symfonyDeterministicReport(t, filepath.Join(root, dir.Name()))
			symfonyValidateCandidates(t, report)
		})
	}
}

func TestSymfonySourceKey(t *testing.T) {
	root := os.Getenv("ZAZZLES_VULN_SYMFONY")
	if root == "" {
		t.Skip("set ZAZZLES_VULN_SYMFONY to the pinned Symfony sample checkout")
	}
	symfonyCheckCheckout(t, root)
	defer symfonyCheckCheckout(t, root)
	report := symfonyDeterministicReport(t, root)
	names := symfonyEntries(t, report)
	t.Run("component-selection", func(t *testing.T) { symfonyValidateCandidates(t, report) })
	t.Run("entry-access", func(t *testing.T) { symfonyEntryAccess(t, report) })

	for _, row := range readSymfonyKey(t) {
		t.Run(row.ID, func(t *testing.T) {
			var matches []analysis.CandidateUse
			for _, use := range report.Uses {
				if row.matches(use) && (row.Expect != "no_record" || len(row.EntryNames) == 0 || slices.Contains(row.EntryNames, names[use.EntryID])) {
					matches = append(matches, use)
				}
			}
			if row.Expect == "only_lines" && row.Anchors != nil {
				symfonyReportWideControl(t, row, report)
				return
			}
			switch row.Expect {
			case "positive":
				symfonyPositive(t, row, matches, names, report)
			case "present":
				if len(matches) == 0 {
					t.Fatal("assessment-dependent candidate is absent")
				}
				if row.ID == "SYM-VAL-R01" {
					for _, field := range []string{"s", "email"} {
						if !slices.ContainsFunc(matches, func(u analysis.CandidateUse) bool {
							return u.Check != nil && u.Check.ID == "automatic-php-query" && slices.Contains(u.Check.Fields, field)
						}) {
							t.Errorf("automatic query check is missing field %q", field)
						}
					}
				}
			default:
				symfonyControl(t, row, matches)
			}
		})
	}
}

func symfonyCheckCheckout(t *testing.T, root string) {
	t.Helper()
	head, err := exec.Command("git", "-C", root, "rev-parse", "HEAD").Output()
	if err != nil || strings.TrimSpace(string(head)) != symfonySamplePin {
		t.Fatalf("sample revision %q, want %s (%v)", head, symfonySamplePin, err)
	}
	status, err := exec.Command("git", "-C", root, "status", "--porcelain", "--ignored").Output()
	if err != nil || len(status) != 0 {
		t.Fatalf("sample must be clean including ignored paths (%v):\n%s", err, status)
	}
}

func symfonyDeterministicReport(t *testing.T, root string) *analysis.AnalysisReport {
	t.Helper()
	var previous []byte
	var report *analysis.AnalysisReport
	for i := range 2 {
		if root == os.Getenv("ZAZZLES_VULN_SYMFONY") {
			symfonyCheckCheckout(t, root)
		}
		var err error
		report, err = Analyze(root, "")
		if root == os.Getenv("ZAZZLES_VULN_SYMFONY") {
			symfonyCheckCheckout(t, root)
		}
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if i == 1 && !bytes.Equal(previous, raw) {
			t.Fatal("analysis JSON changed across two offline scans")
		}
		previous = raw
	}
	return report
}

func symfonyValidateCandidates(t *testing.T, report *analysis.AnalysisReport) {
	t.Helper()
	client, err := judge.New("openai", "fixture-model", "offline-preview-key")
	if err != nil {
		t.Fatal(err)
	}
	for _, use := range report.Uses {
		anchor := use.Sink.Span
		if _, err := analysispacks.Select(use); err != nil {
			t.Errorf("%s %s:%d selection: %v", use.Kind, anchor.File, anchor.StartLine, err)
			continue
		}
		if trace, err := client.Preview(use); err == nil && bytes.Contains(trace.Request, []byte("#VULNERABILITY")) {
			t.Errorf("%s %s:%d decision preview contains a sample annotation", use.Kind, anchor.File, anchor.StartLine)
		}
	}
}

func symfonyEntries(t *testing.T, report *analysis.AnalysisReport) map[string]string {
	t.Helper()
	for _, gap := range report.Gaps {
		if gap.Kind == "parse_error" {
			t.Errorf("sample parse error at %s", gap.At.File)
		}
	}
	guide, err := os.ReadFile(filepath.Join("..", "..", "..", ".zazz", "evaluation", "vuln-symfony-detection-guide.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines, _, _ := strings.Cut(string(guide), "## Answer key")
	route := regexp.MustCompile("(?m)^\\| `((?:ANY|GET|POST) [^`]+)` \\|")
	expected := map[string]int{"FILE /public/index.php": 1, "FILE /public/info.php": 1}
	for _, match := range route.FindAllStringSubmatch(lines, -1) {
		expected[match[1]]++
	}
	if len(expected) != 33 || len(report.Entries) != 34 {
		t.Errorf("expected 33 HTTP and 34 total entries, guide=%d report=%d", len(expected), len(report.Entries))
	}
	names := map[string]string{}
	var browser int
	for _, entry := range report.Entries {
		names[entry.ID] = entry.Name
		if entry.Kind == "browser" {
			browser++
			continue
		}
		if expected[entry.Name] != 1 {
			t.Errorf("unexpected entry %s", entry.Name)
		}
		expected[entry.Name]--
	}
	for name, count := range expected {
		if count > 0 {
			t.Errorf("missing entry %s", name)
		}
	}
	if browser != 1 {
		t.Errorf("expected one browser entry, got %d", browser)
	}
	return names
}

type symfonyKeyRow struct {
	ID, Kind, File, Expect string
	Line                   int
	Lines                  []int
	Anchors                map[string][]int
	Source                 []json.RawMessage
	EntryNames             []string `json:"entry_names"`
	MaxUses                int      `json:"max_uses"`
	MinUses                int      `json:"min_uses"`
	GuardKind              string   `json:"guard_kind"`
	EntryRoles             []string `json:"entry_roles"`
	EachAnchor             bool     `json:"each_anchor"`
}

// symfonyLaneRows are the rows of the application-security lane.
// The 37 rows of PR #39 are counted separately and unchanged.
var symfonyLaneRows = []string{
	"SYM-INFO-01", "SYM-INFO-N01", "SYM-MASS-01", "SYM-MASS-N01", "SYM-MASS-N02",
	"SYM-AUTHZ-01", "SYM-AUTHZ-02", "SYM-AUTHZ-03", "SYM-AUTHZ-04", "SYM-LOCAL-01",
	"SYM-AUTHZ-N01", "SYM-AUTHZ-N02", "SYM-AUTHZ-N03", "SYM-AUTHZ-N04", "SYM-AUTHZ-N05", "SYM-AUTHZ-N06", "SYM-AUTHZ-N07",
	"SYM-LOCAL-N01", "SYM-LOCAL-N02", "SYM-LOCAL-02", "SYM-AUTHZ-R01",
	"SYM-ENUM-01", "SYM-ENUM-02", "SYM-RESET-01", "SYM-HASH-01",
	"SYM-ENUM-N01", "SYM-ENUM-N02", "SYM-RESET-N01", "SYM-HASH-N01",
}

func readSymfonyKey(t *testing.T) []symfonyKeyRow {
	t.Helper()
	file, err := os.ReadFile(filepath.Join("..", "..", "..", ".zazz", "evaluation", "recall-gap-inventory", "cases.json"))
	if err != nil {
		t.Fatal(err)
	}
	var key struct {
		Pins  map[string]string
		Cases []struct {
			symfonyKeyRow
			App string
		}
	}
	if err := json.Unmarshal(file, &key); err != nil {
		t.Fatal(err)
	}
	if key.Pins["vuln-symfony"] != symfonySamplePin {
		t.Fatal("frozen key pin does not match sample pin")
	}
	var rows []symfonyKeyRow
	var base, lane int
	for _, row := range key.Cases {
		if row.App == "vuln-symfony" {
			rows = append(rows, row.symfonyKeyRow)
			if slices.Contains(symfonyLaneRows, row.ID) {
				lane++
			} else {
				base++
			}
		}
	}
	if base != 37 {
		t.Fatalf("frozen Symfony key contains %d rows, want 37", base)
	}
	if lane != len(symfonyLaneRows) {
		t.Fatalf("frozen Symfony key contains %d lane rows, want %d", lane, len(symfonyLaneRows))
	}
	return rows
}

func (r symfonyKeyRow) matches(u analysis.CandidateUse) bool {
	s := u.Sink.Span
	return u.Kind == r.Kind && (r.File == "" || s.File == r.File) &&
		(r.Line == 0 || s.StartLine == r.Line) &&
		(len(r.Lines) == 0 || slices.Contains(r.Lines, s.StartLine)) &&
		(r.Anchors == nil || slices.Contains(r.Anchors[s.File], s.StartLine))
}

func symfonyPositive(t *testing.T, row symfonyKeyRow, uses []analysis.CandidateUse, entries map[string]string, report *analysis.AnalysisReport) {
	t.Helper()
	entriesByRow := map[string][]string{
		"SYM-SQL-01": {"GET /search"}, "SYM-SQL-02": {"POST /login"},
		"SYM-XSS-01": {"GET /search"}, "SYM-XSS-02": {"ANY /post/{post}"}, "SYM-XSS-03": {"ANY /post/{post}"},
		"SYM-CMD-01": {"ANY /", "ANY /post/{post}"}, "SYM-CMD-02": {"GET /user/avatar/resize/{user}"},
		"SYM-PATH-01": {"GET /legal/content"}, "SYM-PATH-02": {"GET /user/avatar/delete/{user}"},
		"SYM-PATH-03": {"POST /user/avatar/url/{user}"}, "SYM-SSRF-01": {"POST /user/avatar/url/{user}"},
		"SYM-UPLOAD-01": {"POST /user/avatar/{user}"}, "SYM-SSTI-01": {"ANY /post/{post}"}, "SYM-DESER-01": {"GET /search"},
		"SYM-INFO-01": {"FILE /public/info.php"}, "SYM-MASS-01": {"POST /user/edit/"},
		"SYM-AUTHZ-01": {"POST /user/role/{user}"}, "SYM-AUTHZ-02": {"POST /user/password/{user}"},
		"SYM-AUTHZ-03": {"POST /user/email/{user}"}, "SYM-AUTHZ-04": {"GET /user/avatar/delete/{user}"},
		"SYM-LOCAL-01": {"ANY /local/promote/{user}"},
		"SYM-ENUM-01":  {"POST /register"}, "SYM-ENUM-02": {"ANY /reset"}, "SYM-RESET-01": {"ANY /reset"},
		"SYM-HASH-01": {"ANY /admin/create", "POST /register", "ANY /reset/{email}/{token}", "POST /user/password/{user}", "POST /login"},
	}
	storage := map[string]string{
		"SYM-XSS-02": "php-sql:comment.content", "SYM-XSS-03": "php-sql:user.about_me",
		"SYM-CMD-02": "php-sql:user.avatar", "SYM-PATH-02": "php-sql:user.avatar",
		"SYM-SSTI-01": "php-sql:user.about_me",
	}[row.ID]
	var sourceFile string
	var sourceLine int
	if len(row.Source) == 2 {
		if json.Unmarshal(row.Source[0], &sourceFile) != nil || json.Unmarshal(row.Source[1], &sourceLine) != nil {
			t.Fatal("malformed source anchor")
		}
	}
	for _, name := range entriesByRow[row.ID] {
		var failures []string
		for _, u := range uses {
			if entries[u.EntryID] != name {
				continue
			}
			if detail := symfonyPositiveEvidence(row.ID, u, sourceFile, sourceLine, storage, report); detail == "" {
				failures = nil
				break
			} else {
				failures = append(failures, detail)
			}
		}
		if row.MinUses > 0 && !row.EachAnchor {
			n := 0
			for _, u := range uses {
				if entries[u.EntryID] == name {
					n++
				}
			}
			if n < row.MinUses {
				t.Errorf("%s has %d candidates, want at least %d", name, n, row.MinUses)
			}
		}
		if failures == nil && !slices.ContainsFunc(uses, func(u analysis.CandidateUse) bool { return entries[u.EntryID] == name }) {
			t.Errorf("%s missing candidate at %s:%d", name, row.File, row.Line)
		} else if len(failures) > 0 {
			t.Errorf("%s at %s:%d misses evidence: %s", name, row.File, row.Line, strings.Join(failures, "; "))
		}
	}
	if len(entriesByRow[row.ID]) == 0 {
		t.Fatal("positive row has no expected entry")
	}
	if row.EachAnchor {
		n := 0
		for _, lines := range row.Anchors {
			n += len(lines)
		}
		if row.MinUses > 0 && len(uses) < row.MinUses || n < row.MinUses {
			t.Errorf("%d candidates over %d anchors, want at least %d", len(uses), n, row.MinUses)
		}
		for file, lines := range row.Anchors {
			for _, line := range lines {
				if !slices.ContainsFunc(uses, func(u analysis.CandidateUse) bool {
					return u.Sink.Span.File == file && u.Sink.Span.StartLine == line && symfonyPositiveEvidence(row.ID, u, sourceFile, sourceLine, storage, report) == ""
				}) {
					t.Errorf("anchor %s:%d has no candidate with its evidence", file, line)
				}
			}
		}
	}
}

func symfonyPositiveEvidence(id string, u analysis.CandidateUse, sourceFile string, sourceLine int, storage string, report *analysis.AnalysisReport) string {
	if u.Completeness != nil && len(u.Completeness.Blockers) > 0 {
		return fmt.Sprintf("blockers %v", u.Completeness.Blockers)
	}
	if u.Kind == analysis.AuthorizationKind {
		return symfonyAuthorizationEvidence(id, u, report)
	}
	if detail, ok := symfonyAccountEvidence(id, u); ok {
		return detail
	}
	if u.Kind == analysis.ExposureKind {
		// An operation-centered claim has no request source (lane contract 2.7).
		if u.Exposure == nil || u.Exposure.Operation != "phpinfo" || u.Exposure.EntryServed != "yes" {
			return "missing diagnostic operation facts"
		}
		return ""
	}
	witness := slices.ContainsFunc(u.Dependencies, func(dep analysis.Dependency) bool {
		if dep.Source.Kind != "input_source" {
			return false
		}
		if storage != "" {
			return dep.StorageKey == storage
		}
		return dep.Source.Span.File == sourceFile && dep.Source.Span.StartLine == sourceLine
	})
	if !witness {
		return "missing anchored request or storage-writer dependency"
	}
	switch id {
	case "SYM-CMD-01":
		if !slices.ContainsFunc(u.Context, func(e analysis.Evidence) bool { return e.Kind == "configuration_precondition" }) {
			return "missing configuration precondition"
		}
		if u.Completeness == nil || !slices.ContainsFunc(u.Completeness.Evidence["control_flow"], func(e analysis.Evidence) bool {
			return strings.HasSuffix(e.Span.File, "/Analytics.php") && e.Span.StartLine == 40
		}) {
			return "missing URL format guard"
		}
	case "SYM-CMD-02", "SYM-PATH-02":
		for _, line := range []int{98, 239} {
			found := slices.ContainsFunc(u.Dependencies, func(dep analysis.Dependency) bool {
				return dep.StorageKey == storage && slices.ContainsFunc(append([]analysis.Evidence{dep.Source}, dep.Transfers...), func(e analysis.Evidence) bool {
					return strings.HasSuffix(e.Span.File, "/UserController.php") && e.Span.StartLine == line
				})
			})
			if !found {
				return fmt.Sprintf("missing stored writer at UserController.php:%d", line)
			}
		}
	case "SYM-UPLOAD-01":
		if u.Upload == nil || u.Upload.ExtensionOrigin != "client" || u.Upload.DestinationServed != "yes" {
			return "missing client extension or served destination evidence"
		}
	case "SYM-MASS-01":
		m := u.MassAssignment
		if m == nil || m.Shape != analysis.MassAssignmentPropertyWrite || m.TargetStored != "yes" {
			return "missing dynamic property write facts"
		}
		for key, role := range map[string]string{"php-sql:user.is_admin": analysis.RoleSource, "php-sql:user.password": analysis.RoleCredential, "php-sql:user.email": analysis.RoleLoginIdentifier} {
			if !slices.ContainsFunc(m.SecurityFields, func(f analysis.SecurityField) bool { return f.StorageKey == key && slices.Contains(f.Roles, role) }) {
				return "missing census role " + role + " on " + key
			}
		}
	}
	return ""
}

// symfonyReportWideControl checks a report-wide only_lines row: every
// candidate of the kind sits at a listed anchor, at most MaxUses of them.
func symfonyReportWideControl(t *testing.T, row symfonyKeyRow, report *analysis.AnalysisReport) {
	t.Helper()
	count := 0
	for _, u := range report.Uses {
		if u.Kind != row.Kind {
			continue
		}
		count++
		if s := u.Sink.Span; !slices.Contains(row.Anchors[s.File], s.StartLine) {
			t.Errorf("%s candidate outside the key at %s:%d", row.Kind, s.File, s.StartLine)
		}
	}
	if row.MaxUses > 0 && count > row.MaxUses {
		t.Errorf("%d %s candidates, want at most %d", count, row.Kind, row.MaxUses)
	}
}

func symfonyControl(t *testing.T, row symfonyKeyRow, uses []analysis.CandidateUse) {
	t.Helper()
	if (row.Expect == "encoded" || row.Expect == "guarded") && len(uses) == 0 {
		t.Fatal(row.Expect + " control is absent")
	}
	for _, u := range uses {
		var pass bool
		switch row.Expect {
		case "not_raw":
			pass = u.XSS != nil && u.XSS.Protection != "raw"
		case "encoded":
			pass = u.XSS != nil && u.XSS.Protection == "encoded"
		case "not_decisive":
			pass = u.Completeness != nil && len(u.Completeness.Blockers) > 0 ||
				!slices.ContainsFunc(u.Dependencies, func(d analysis.Dependency) bool { return d.Source.Kind == "input_source" })
		case "bound":
			pass = !slices.ContainsFunc(u.Gaps, func(g analysis.Gap) bool { return g.Kind == "query_text_interpolated" })
		case "no_record":
			pass = false
		case "guarded":
			pass = symfonyGuarded(row, u)
		default:
			t.Fatalf("unknown frozen control expectation %q", row.Expect)
		}
		if !pass {
			t.Errorf("%s control failed at %s:%d", row.Expect, u.Sink.Span.File, u.Sink.Span.StartLine)
		}
	}
}

func symfonyGuarded(row symfonyKeyRow, u analysis.CandidateUse) bool {
	if u.Authorization == nil || u.EntryFacts == nil || u.EntryFacts.Access == nil {
		return false
	}
	if row.GuardKind != "" && !slices.ContainsFunc(u.Authorization.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == row.GuardKind }) {
		return false
	}
	for _, role := range row.EntryRoles {
		if !slices.Contains(u.EntryFacts.Access.Roles, role) {
			return false
		}
	}
	return row.GuardKind != "" || len(row.EntryRoles) > 0
}

func symfonyAuthorizationEvidence(id string, u analysis.CandidateUse, report *analysis.AnalysisReport) string {
	f := u.Authorization
	if f == nil || f.SubjectProvenance != analysis.SubjectRequestSelected {
		return "missing request-selected subject"
	}
	if u.EntryFacts == nil || u.EntryFacts.Access == nil {
		return "missing entry access"
	}
	access := u.EntryFacts.Access
	switch id {
	case "SYM-AUTHZ-01":
		if !symfonyHasRole(f, "php-sql:user.is_admin", analysis.RoleSource) || !slices.Contains(f.Facets, analysis.FacetFunctionLevel) {
			return "missing role_source write"
		}
		if access.Authentication != analysis.AccessRequired || !slices.Contains(access.Roles, "ROLE_USER") {
			return "entry access is not ROLE_USER"
		}
		if len(f.Guards) != 0 {
			return "unexpected guard"
		}
		if !slices.ContainsFunc(f.PeerAccess, func(p analysis.PeerAccess) bool { return p.Entry == "ANY /admin/create" }) {
			return "peer access lacks ANY /admin/create"
		}
	case "SYM-AUTHZ-02":
		if !symfonyHasRole(f, "php-sql:user.password", analysis.RoleCredential) || !slices.Contains(f.Facets, analysis.FacetObjectLevel) {
			return "missing credential write"
		}
		if slices.ContainsFunc(f.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == analysis.GuardOwnership }) {
			return "unexpected ownership guard"
		}
		if slices.ContainsFunc(f.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == analysis.GuardUnclassified }) ||
			u.Completeness != nil && slices.ContainsFunc(u.Completeness.Blockers, func(g analysis.Gap) bool { return g.Kind == analysis.GuardUnclassified }) {
			return "inline input validation was recorded as an unclassified authorization guard or blocker"
		}
	case "SYM-AUTHZ-03":
		if !symfonyHasRole(f, "php-sql:user.email", analysis.RoleLoginIdentifier) {
			return "missing login_identifier write"
		}
	case "SYM-AUTHZ-04":
		if f.MethodSafe != "yes" {
			return "method_safe is not yes"
		}
		if slices.ContainsFunc(f.Guards, func(g analysis.AuthorizationGuard) bool { return g.Kind == analysis.GuardOwnership }) {
			return "unexpected ownership guard"
		}
	case "SYM-LOCAL-01":
		if access.Authentication != analysis.AccessNone {
			return "entry authentication is not none"
		}
		if !slices.Contains(f.Facets, analysis.FacetFunctionLevel) || !symfonyHasRole(f, "php-sql:user.is_admin", analysis.RoleSource) {
			return "missing role_source write"
		}
		if len(f.Guards) != 1 || f.Guards[0].Kind != analysis.GuardAddress {
			return "guard is not only address_check"
		}
		if !symfonyListsSSRF(f, report) {
			return "server_side_requests lacks the avatar URL request"
		}
	}
	return ""
}

func symfonyHasRole(f *analysis.AuthorizationFacts, key, role string) bool {
	return slices.ContainsFunc(f.SecurityFields, func(field analysis.SecurityFieldFact) bool {
		return field.StorageKey == key && slices.Contains(field.Roles, role)
	})
}

func symfonyListsSSRF(f *analysis.AuthorizationFacts, report *analysis.AnalysisReport) bool {
	if report == nil {
		return false
	}
	for _, u := range report.Uses {
		if u.Kind != "ssrf_candidate" || u.EntryFacts == nil || u.EntryFacts.Name != "POST /user/avatar/url/{user}" {
			continue
		}
		if slices.Contains(f.ServerSideRequests, u.ID) {
			return true
		}
	}
	return false
}

func symfonyEntryAccess(t *testing.T, report *analysis.AnalysisReport) {
	t.Helper()
	admin := map[string]bool{"ANY /admin": true, "ANY /admin/delete/{user}": true, "ANY /admin/create": true}
	user := map[string]bool{
		"ANY /user": true, "POST /user/password/{user}": true, "POST /user/email/{user}": true,
		"POST /user/avatar/{user}": true, "POST /user/avatar/url/{user}": true, "GET /user/avatar/delete/{user}": true,
		"GET /user/avatar/resize/{user}": true, "POST /user/about/": true, "GET /user/edit/": true,
		"POST /user/edit/": true, "POST /user/role/{user}": true,
	}
	var routes, files int
	for _, e := range report.Entries {
		if e.Kind != "http" {
			continue
		}
		if strings.HasPrefix(e.Name, "FILE ") {
			files++
			if e.Access != nil {
				t.Errorf("%s carries access", e.Name)
			}
			continue
		}
		routes++
		if e.Access == nil {
			t.Errorf("%s has no access", e.Name)
			continue
		}
		switch {
		case admin[e.Name]:
			if e.Access.Authentication != analysis.AccessRequired || !slices.Equal(e.Access.Roles, []string{"ROLE_ADMIN"}) {
				t.Errorf("%s access %+v, want required ROLE_ADMIN", e.Name, e.Access)
			}
		case user[e.Name]:
			if e.Access.Authentication != analysis.AccessRequired || !slices.Equal(e.Access.Roles, []string{"ROLE_USER"}) {
				t.Errorf("%s access %+v, want required ROLE_USER", e.Name, e.Access)
			}
		default:
			if e.Access.Authentication != analysis.AccessNone || len(e.Access.Roles) != 0 {
				t.Errorf("%s access %+v, want none", e.Name, e.Access)
			}
		}
	}
	if files != 2 || routes != 31 {
		t.Errorf("access census files=%d routes=%d, want 2 and 31", files, routes)
	}
}

// symfonyAccountEvidence checks the account facts of the sample rows.
func symfonyAccountEvidence(id string, u analysis.CandidateUse) (string, bool) {
	switch u.Kind {
	case analysis.AccountEnumerationKind:
		f := u.Enumeration
		if f == nil || len(f.Found) == 0 || len(f.NotFound) == 0 || slices.Equal(f.Found, f.NotFound) {
			return "missing differing response lists", true
		}
		if u.EntryFacts == nil || u.EntryFacts.Access == nil || u.EntryFacts.Access.Authentication != analysis.AccessNone {
			return "entry access is not none", true
		}
		return "", true
	case analysis.RecoveryDeliveryKind:
		f := u.Recovery
		if f == nil || f.SecretSource.Span.File != "src/Controller/PasswordResetController.php" || f.SecretSource.Span.StartLine != 40 || f.SecretStrength != analysis.SecretCSPRNG {
			return "missing csprng secret at PasswordResetController.php:40", true
		}
		if f.RecipientValidated != analysis.RecipientPartial || f.RecipientCount != analysis.RecipientCountRequest || len(f.ShapeUses) != 2 {
			return fmt.Sprintf("recipient facts %s %s %d", f.RecipientValidated, f.RecipientCount, len(f.ShapeUses)), true
		}
		if a, b := f.ShapeUses[0].Span, f.ShapeUses[1].Span; a.File != "src/Controller/PasswordResetController.php" || a.StartLine != 34 || b.File != "src/Services/Mail.php" || b.StartLine != 23 {
			return "use sites are not :34 and Mail.php:23", true
		}
		if f.StoredField != "php-sql:user.reset" || !slices.ContainsFunc(f.SecurityFields, func(s analysis.SecurityFieldFact) bool {
			return s.StorageKey == f.StoredField && slices.Contains(s.Roles, analysis.RoleRecoverySecret)
		}) {
			return "stored field lacks recovery_secret", true
		}
		return "", true
	case analysis.PasswordHashKind:
		f := u.PasswordHash
		if f == nil || f.Algorithm != "md5" || f.Salted != "no" {
			return "missing md5 digest facts", true
		}
		want := analysis.BasisCredentialField
		if u.Sink.Span.File == "src/Security/Hasher/Md5Hasher.php" {
			want = analysis.BasisHasherClass
		}
		if f.Basis != want {
			return "basis " + f.Basis + ", want " + want, true
		}
		return "", true
	}
	return "", false
}
