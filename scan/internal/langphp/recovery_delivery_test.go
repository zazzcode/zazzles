package langphp

import (
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

type observedSend struct {
	entry, contract, recipients, content string
	secret                               bool
}

// observeAccount runs an analysis and returns the mail sends it modeled and
// the census after the account post-pass, read from the set's state.
func observeAccount(t *testing.T, root string) (*analysis.AnalysisReport, []observedSend, map[string][]string) {
	t.Helper()
	s, err := newPHPSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	r, err := s.report("", nil)
	if err != nil {
		t.Fatal(err)
	}
	var sends []observedSend
	for _, m := range s.accountState().sends {
		var rec, con []string
		secret := false
		for _, o := range m.recipients {
			rec = append(rec, o.method)
		}
		for _, o := range m.content {
			con = append(con, o.method)
			secret = secret || o.value.secret != nil
		}
		sends = append(sends, observedSend{m.entry, m.contract, strings.Join(rec, ","), strings.Join(con, ","), secret})
	}
	census := map[string][]string{}
	for _, c := range s.census {
		for key, field := range c.fields {
			census[key] = field.roles
		}
	}
	return r, sends, census
}

// Mailer cases: the recipient and content operands of each send form.
func TestPHPMailer(t *testing.T) {
	r, sends, _ := observeAccount(t, "testdata/symfony/account")
	find := func(entry string) []observedSend {
		var out []observedSend
		for _, s := range sends {
			if s.entry == entry {
				out = append(out, s)
			}
		}
		return out
	}
	for _, tt := range []struct {
		id, entry string
		want      observedSend
	}{
		{"ML-01", "POST /mail/one", observedSend{contract: "api.symfony-mailer-v1", recipients: "to", content: "subject,html"}},
		{"ML-02", "POST /mail/many", observedSend{contract: "api.symfony-mailer-v1", recipients: "addTo,cc,bcc", content: "text"}},
		{"ML-03", "POST /mail/templated", observedSend{contract: "api.symfony-mailer-v1", recipients: "to", content: "context"}},
		{"ML-04", "POST /mail/link", observedSend{contract: "api.symfony-mailer-v1", recipients: "to", content: "html", secret: true}},
		{"ML-05", "POST /mail/native", observedSend{contract: "api.php-mail-v1", recipients: "to", content: "subject,message"}},
	} {
		t.Run(tt.id, func(t *testing.T) {
			got := find(tt.entry)
			if len(got) != 1 {
				t.Fatalf("%d sends under %s, want 1 (all %+v)", len(got), tt.entry, sends)
			}
			g := got[0]
			g.entry = ""
			if g != tt.want {
				t.Fatalf("send %+v, want %+v", g, tt.want)
			}
		})
	}
	t.Run("ML-06", func(t *testing.T) {
		for _, entry := range []string{"POST /mail/one", "POST /mail/many", "POST /mail/templated", "POST /mail/native"} {
			if n := len(accountUses(r, analysis.RecoveryDeliveryKind, entry)); n != 0 {
				t.Fatalf("%s has %d recovery records for a mail with no secret", entry, n)
			}
		}
	})
}

// Recovery cases: each recipient origin and the stored-secret census role.
func TestRecoveryDelivery(t *testing.T) {
	r, _, census := observeAccount(t, "testdata/symfony/account")
	const resetKey = "php-sql:Account.resetCode"
	type want struct {
		file                       string
		line                       int
		validated, count, strength string
		origin                     string
		uses                       []string
		stored                     string
	}
	for _, tt := range []struct {
		id, entry string
		want      *want
	}{
		{"RC-01", "POST /recover/stored", nil},
		{"RC-02", "POST /recover/direct", &want{"src/Controller/RecoveryController.php", 38, analysis.RecipientFull, analysis.RecipientCountOne, analysis.SecretCSPRNG, analysis.RecipientRequestValue, nil, resetKey}},
		{"RC-03", "POST /recover/service", &want{"src/Service/ResetMailer.php", 28, analysis.RecipientPartial, analysis.RecipientCountRequest, analysis.SecretCSPRNG, analysis.RecipientRequestValue,
			[]string{"src/Controller/RecoveryController.php:47", "src/Service/ResetMailer.php:22"}, resetKey}},
		{"RC-04", "POST /recover/inline", &want{"src/Controller/RecoveryController.php", 63, analysis.RecipientPartial, analysis.RecipientCountRequest, analysis.SecretCSPRNG, analysis.RecipientRequestValue,
			[]string{"src/Controller/RecoveryController.php:59", "src/Controller/RecoveryController.php:62"}, resetKey}},
		{"RC-05", "POST /recover/blind", &want{"src/Controller/RecoveryController.php", 75, analysis.RecipientNone, analysis.RecipientCountOne, analysis.SecretCSPRNG, analysis.RecipientRequestValue, nil, ""}},
		{"RC-06", "POST /recover/weak", &want{"src/Controller/RecoveryController.php", 87, analysis.RecipientFull, analysis.RecipientCountOne, analysis.SecretWeak, analysis.RecipientStoredField, nil, resetKey}},
		{"RC-07", "POST /recover/stored", nil},
		{"RC-08", "POST /recover/echo", nil},
		{"RC-11", "POST /recover/typed", &want{"src/Service/ResetNotifier.php", 8, analysis.RecipientPartial, analysis.RecipientCountRequest, analysis.SecretCSPRNG, analysis.RecipientRequestValue,
			[]string{"src/Controller/NotifyController.php:17", "src/Service/ResetNotifier.php:6"}, ""}},
	} {
		t.Run(tt.id, func(t *testing.T) {
			uses := accountUses(r, analysis.RecoveryDeliveryKind, tt.entry)
			if tt.want == nil {
				if len(uses) != 0 {
					t.Fatalf("%d records, want none:\n%s", len(uses), accountSummary(r, analysis.RecoveryDeliveryKind))
				}
				return
			}
			if len(uses) != 1 {
				t.Fatalf("%d records, want 1:\n%s", len(uses), accountSummary(r, analysis.RecoveryDeliveryKind))
			}
			u, w := uses[0], tt.want
			f := u.Recovery
			if u.Sink.Span.File != w.file || u.Sink.Span.StartLine != w.line {
				t.Fatalf("sink %s:%d, want %s:%d", u.Sink.Span.File, u.Sink.Span.StartLine, w.file, w.line)
			}
			if f.RecipientValidated != w.validated || f.RecipientCount != w.count || f.SecretStrength != w.strength || f.RecipientOrigin != w.origin {
				t.Fatalf("facts %+v", f)
			}
			var uses2 []string
			for _, e := range f.ShapeUses {
				uses2 = append(uses2, e.Span.File+":"+strconv.Itoa(e.Span.StartLine))
			}
			if !slices.Equal(uses2, w.uses) {
				t.Fatalf("shape uses %v, want %v", uses2, w.uses)
			}
			if f.StoredField != w.stored {
				t.Fatalf("stored field %q, want %q", f.StoredField, w.stored)
			}
			if w.stored != "" && !slices.ContainsFunc(f.SecurityFields, func(s analysis.SecurityFieldFact) bool {
				return s.StorageKey == w.stored && slices.Contains(s.Roles, analysis.RoleRecoverySecret)
			}) {
				t.Fatalf("security fields %+v lack %s", f.SecurityFields, analysis.RoleRecoverySecret)
			}
			if err := f.Validate(); err != nil {
				t.Fatal(err)
			}
			if u.APIModel == nil || "api."+u.APIModel.ID != f.MailContract {
				t.Fatalf("contract %+v / %s", u.APIModel, f.MailContract)
			}
		})
	}
	t.Run("RC-01 census", func(t *testing.T) {
		if !slices.Contains(census[resetKey], analysis.RoleRecoverySecret) {
			t.Fatalf("census %s roles %v", resetKey, census[resetKey])
		}
	})
}

// Recovery cases on a transfer project and a plain-PHP project.
func TestRecoveryDeliveryTransfer(t *testing.T) {
	for _, tt := range []struct {
		id, root, entry, file string
		line                  int
		validated, contract   string
		uses                  []string
	}{
		{"RC-09", "testdata/symfony/account-transfer", "POST /api/members/recover", "src/Api/MemberApi.php", 62, analysis.RecipientPartial, "api.symfony-mailer-v1",
			[]string{"src/Api/MemberApi.php:56", "src/Api/MemberApi.php:61"}},
		{"RC-10", "testdata/account-plain", "FILE /forgot.php", "forgot.php", 8, analysis.RecipientFull, "api.php-mail-v1", nil},
	} {
		t.Run(tt.id, func(t *testing.T) {
			r := phpAnalyze(t, tt.root, "")
			uses := accountUses(r, analysis.RecoveryDeliveryKind, tt.entry)
			if len(uses) != 1 {
				t.Fatalf("%d records, want 1:\n%s", len(uses), accountSummary(r, analysis.RecoveryDeliveryKind))
			}
			u := uses[0]
			f := u.Recovery
			if u.Sink.Span.File != tt.file || u.Sink.Span.StartLine != tt.line || f.RecipientValidated != tt.validated || f.MailContract != tt.contract || f.SecretStrength != analysis.SecretCSPRNG {
				t.Fatalf("record %s:%d %+v", u.Sink.Span.File, u.Sink.Span.StartLine, f)
			}
			var got []string
			for _, e := range f.ShapeUses {
				got = append(got, e.Span.File+":"+strconv.Itoa(e.Span.StartLine))
			}
			if !slices.Equal(got, tt.uses) {
				t.Fatalf("shape uses %v, want %v", got, tt.uses)
			}
			if !hasInputDependency(u) {
				t.Fatal("no request dependency")
			}
		})
	}
}

// Mail content is a delivery sink for the recovery claim only: a request
// value in html() or text() content produces no xss_candidate.
func TestMailContentNotRenderingSink(t *testing.T) {
	for _, root := range []string{"testdata/symfony/account", "testdata/symfony/account-transfer", "testdata/account-plain"} {
		r := phpAnalyze(t, root, "")
		for _, u := range r.Uses {
			if u.Kind != "xss_candidate" {
				continue
			}
			switch u.Sink.Span.File {
			case "src/Controller/MailController.php", "src/Controller/RecoveryController.php", "src/Service/ResetMailer.php", "src/Api/MemberApi.php", "forgot.php":
				if strings.Contains(u.Sink.Text, "mail") || strings.Contains(u.Sink.Text, "->html(") || strings.Contains(u.Sink.Text, "->text(") || strings.Contains(u.Sink.Text, "send(") {
					t.Fatalf("%s: xss_candidate at a mail operand %s:%d %q", root, u.Sink.Span.File, u.Sink.Span.StartLine, u.Sink.Text)
				}
			}
		}
		if len(phpUsesOfKind(r, analysis.RecoveryDeliveryKind))+len(phpUsesOfKind(r, analysis.AccountEnumerationKind)) == 0 {
			t.Fatalf("%s: fixture produced no account record", root)
		}
	}
	r := phpAnalyze(t, "testdata/symfony/account", "")
	for _, u := range r.Uses {
		if u.Kind == "xss_candidate" && u.Sink.Span.File == "src/Controller/MailController.php" {
			t.Fatalf("xss_candidate in the mail controller at %d: %q", u.Sink.Span.StartLine, u.Sink.Text)
		}
	}
}
