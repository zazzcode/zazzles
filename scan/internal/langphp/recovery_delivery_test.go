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
// the census after the account post-pass.
func observeAccount(t *testing.T, root string) (*analysis.AnalysisReport, []observedSend, map[string][]string) {
	t.Helper()
	var sends []observedSend
	census := map[string][]string{}
	mailSendHook = func(entry string, s phpMailSend) {
		var rec, con []string
		secret := false
		for _, o := range s.recipients {
			rec = append(rec, o.method)
		}
		for _, o := range s.content {
			con = append(con, o.method)
			secret = secret || o.value.secret != nil
		}
		sends = append(sends, observedSend{entry, s.contract, strings.Join(rec, ","), strings.Join(con, ","), secret})
	}
	accountFinishHook = func(s *phpSet) {
		for _, c := range s.census {
			for key, field := range c.fields {
				census[key] = field.roles
			}
		}
	}
	defer func() { mailSendHook, accountFinishHook = nil, nil }()
	return phpAnalyze(t, root, ""), sends, census
}

// Cases ML-01 to ML-06 of branch 3 section 8.
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

// Cases RC-01 to RC-10 of branch 3 section 8.
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
