package langphp

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Recovery-secret delivery (branch 3 D-5 and D-7). A generated secret that
// reaches mail content is recorded with the origin of its recipient and the
// checks that tied the recipient to the account.

// phpSecret is the generated secret a value derives from.
type phpSecret struct {
	source   analysis.Evidence
	strength string // csprng | weak
}

// phpAccountLookup is a lookup whose criteria hold request values.
type phpAccountLookup struct {
	sources map[string]bool
	element *analysis.Evidence // a criterion read with a literal index
}

// phpSecretStore is a stored write of a secret.
type phpSecretStore struct {
	entry, source string
	key           string
	at            analysis.Evidence
	decl          *phpClassDecl
	project       *symfonyProject
}

// phpAccountState is the set-level state of the account adapter.
type phpAccountState struct {
	mails     map[int]*phpMail
	lookups   map[string][]phpAccountLookup           // entry -> lookups
	shapeUses map[string]map[string]analysis.Evidence // entry -> request source -> first array use
	stores    []phpSecretStore
}

// accountFinishHook observes the set after the account post-pass in tests.
var accountFinishHook func(s *phpSet)

func (s *phpSet) accountState() *phpAccountState {
	if s.account == nil {
		s.account = &phpAccountState{mails: map[int]*phpMail{}, lookups: map[string][]phpAccountLookup{}, shapeUses: map[string]map[string]analysis.Evidence{}}
	}
	return s.account
}

func depKey(d phpDep) string {
	return fmt.Sprintf("%s:%d", d.dep.Source.Span.File, d.dep.Source.Span.StartByte)
}

// D-5 secret sources.
var (
	csprngFunctions = map[string]bool{"random_bytes": true, "random_int": true, "openssl_random_pseudo_bytes": true}
	weakFunctions   = map[string]bool{"uniqid": true, "mt_rand": true, "rand": true, "lcg_value": true, "microtime": true, "time": true}
)

// accountCall marks secret sources and records mail(), array spreads and
// password digests on the result of one call.
func (f *phpFlow) accountCall(n *sitter.Node, nodes []*sitter.Node, values []phpValue, v phpValue) phpValue {
	for i, a := range nodes {
		if a.Kind() == "variadic_unpacking" && i < len(values) {
			f.noteArrayUse(a, values[i])
		}
	}
	switch n.Kind() {
	case "function_call_expression":
		name := strings.ToLower(strings.TrimPrefix(f.callName(n), `\`))
		if !f.builtin(name) {
			return v
		}
		switch {
		case csprngFunctions[name]:
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG}
		case weakFunctions[name]:
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretWeak}
		case name == "bin2hex" || name == "base64_encode":
			if len(values) > 0 && values[0].secret != nil {
				v.secret = values[0].secret
			}
		case name == "md5" || name == "sha1":
			if len(values) > 0 && values[0].secret != nil && values[0].secret.strength == analysis.SecretWeak {
				v.secret = values[0].secret
			}
		case name == "mail":
			f.phpMailCall(n, nodes, values)
		}
		v = f.digestCall(n, name, nodes, v)
	case "scoped_call_expression":
		class := strings.TrimPrefix(f.set.classIndex().qualify(f.module, phpText(f.module, phpField(n, "scope")), n.StartByte()), `\`)
		method := strings.ToLower(phpText(f.module, phpField(n, "name")))
		if strings.EqualFold(class, `Symfony\Component\Uid\Uuid`) && method == "v4" || strings.EqualFold(class, `Symfony\Component\String\ByteString`) && method == "fromrandom" {
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG}
		}
	}
	return v
}

// noteArrayUse records a request value used as an array: iterated by
// foreach or spread into a call (D-7).
func (f *phpFlow) noteArrayUse(at *sitter.Node, v phpValue) {
	if f.entry.ID == "" {
		return
	}
	st := f.set.accountState()
	for _, d := range phpInputDeps([]phpValue{v}) {
		if st.shapeUses[f.entry.ID] == nil {
			st.shapeUses[f.entry.ID] = map[string]analysis.Evidence{}
		}
		if _, ok := st.shapeUses[f.entry.ID][depKey(d)]; !ok {
			st.shapeUses[f.entry.ID][depKey(d)] = f.module.evidence("array_use", at)
		}
	}
}

// noteAccountLookup records a finder's request criteria for the recipient
// check of D-7, with the first criterion read through a literal index.
func (f *phpFlow) noteAccountLookup(n *sitter.Node, deps []phpDep) {
	if f.entry.ID == "" || len(deps) == 0 {
		return
	}
	l := phpAccountLookup{sources: map[string]bool{}}
	for _, d := range deps {
		l.sources[depKey(d)] = true
	}
	if args := phpArgs(n); len(args) > 0 {
		phpWalk(args[0], func(c *sitter.Node) {
			if l.element != nil || c.Kind() != "subscript_expression" {
				return
			}
			if _, index := phpSubscriptParts(c); index != nil && (index.Kind() == "integer" || index.Kind() == "string" || index.Kind() == "encapsed_string") {
				e := f.module.evidence("checked_element", c)
				l.element = &e
			}
		})
	}
	st := f.set.accountState()
	st.lookups[f.entry.ID] = append(st.lookups[f.entry.ID], l)
}

// noteSecretStore records a stored write of a secret value.
func (f *phpFlow) noteSecretStore(object phpValue, key string, v phpValue, at *sitter.Node) {
	sec := secretOf(v)
	if sec == nil || key == "" || at == nil {
		return
	}
	st := f.set.accountState()
	st.stores = append(st.stores, phpSecretStore{entry: f.entry.ID, source: spanKey(sec.source.Span), key: key, at: f.authzSink(at), decl: object.classDecl, project: f.symfony})
}

func spanKey(s analysis.Span) string {
	return fmt.Sprintf("%s:%d", s.File, s.StartByte)
}

// noteRecovery records a send whose content carries a secret (D-7).
func (f *phpFlow) noteRecovery(n *sitter.Node, s phpMailSend) {
	if f.report == nil || f.entry.ID == "" {
		return
	}
	var content *phpMailOperand
	var secret *phpSecret
	for i := range s.content {
		if sec := secretOf(s.content[i].value); sec != nil {
			content, secret = &s.content[i], sec
			break
		}
	}
	if content == nil || len(s.recipients) == 0 {
		return
	}
	st := f.set.accountState()
	recipient := s.recipients[0]
	var deps []phpDep
	for _, r := range s.recipients {
		if d := phpInputDeps([]phpValue{r.value}); len(d) > 0 {
			recipient, deps = r, d
			break
		}
	}
	facts := &analysis.RecoveryFacts{SecretSource: secret.source, SecretStrength: secret.strength, Recipient: recipient.at, Content: content.at,
		MailContract: s.contract, SecurityFields: []analysis.SecurityFieldFact{}}
	if len(deps) == 0 {
		facts.RecipientOrigin, facts.RecipientValidated, facts.RecipientCount = analysis.RecipientStoredField, analysis.RecipientFull, analysis.RecipientCountOne
	} else {
		facts.RecipientOrigin = analysis.RecipientRequestValue
		var use *analysis.Evidence
		for _, d := range deps {
			if e, ok := st.shapeUses[f.entry.ID][depKey(d)]; ok {
				use = &e
				break
			}
		}
		var lookup *phpAccountLookup
		for i, l := range st.lookups[f.entry.ID] {
			if slices.ContainsFunc(deps, func(d phpDep) bool { return l.sources[depKey(d)] }) {
				lookup = &st.lookups[f.entry.ID][i]
				break
			}
		}
		facts.RecipientCount = analysis.RecipientCountOne
		if use != nil {
			facts.RecipientCount = analysis.RecipientCountRequest
		}
		switch {
		case lookup != nil && use != nil && lookup.element != nil:
			facts.RecipientValidated = analysis.RecipientPartial
			facts.ShapeUses = []analysis.Evidence{*lookup.element, *use}
		case lookup != nil:
			facts.RecipientValidated = analysis.RecipientFull
		default:
			facts.RecipientValidated = analysis.RecipientNone
		}
	}
	sink := s.at
	id := fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, sink.Span.File, sink.Span.StartByte, analysis.RecoveryDeliveryKind)
	for _, u := range f.report.Uses {
		if u.ID == id {
			return
		}
	}
	dependencies := []analysis.Dependency{}
	for _, d := range deps {
		dependencies = append(dependencies, d.dep)
	}
	binding := sink
	binding.Kind = "sink_binding"
	contract := strings.TrimPrefix(s.contract, "api.")
	f.report.Uses = append(f.report.Uses, analysis.CandidateUse{
		ID: id, EntryID: f.entry.ID, InvocationContextID: f.invocation.ID,
		Kind: analysis.RecoveryDeliveryKind, Sink: sink, Dependencies: dependencies,
		Context: phpDedupeEvidence(f.context), Gaps: append([]analysis.Gap{}, f.gaps...),
		Assessment: analysis.Assessment{Status: "not_run"},
		Recovery:   facts,
		APIModel:   analysispacks.AccountContract(contract),
		Completeness: &analysis.Completeness{
			ClaimKind: "recovery_delivery",
			Required:  []string{"secret_source", "mail_recipient", "mail_content", "control_flow"},
			Scope:     "One generated secret delivered by mail, its recipient's origin and the checks that covered it.",
			Evidence: map[string][]analysis.Evidence{
				"secret_source":  {secret.source},
				"mail_recipient": {recipient.at},
				"mail_content":   {content.at},
				"control_flow":   append([]analysis.Evidence{sink}, f.context...),
				"sink_binding":   {binding},
			},
			Blockers: []analysis.Gap{},
			Coverage: []analysis.Gap{},
		},
	})
}

var phpGetterCall = regexp.MustCompile(`->\s*(get[A-Za-z0-9_]*)\s*\(\s*\)`)

// finishAccount runs after every entry is walked. It fills the stored field
// of each recovery record, adds census role recovery_secret to a stored
// secret field compared with a request value (a recorded secret_check), and
// keeps a stored-address record only for a weak secret behind that check.
func (s *phpSet) finishAccount(out *analysis.AnalysisReport) {
	if out == nil {
		return
	}
	st := s.accountState()
	compared := map[string]bool{}
	for _, store := range st.stores {
		if s.secretCompared(out, store) {
			compared[store.key] = true
			s.addCensusRole(store.project, store.key, analysis.RoleRecoverySecret, store.at)
		}
	}
	kept := out.Uses[:0]
	for _, u := range out.Uses {
		if u.Recovery == nil {
			kept = append(kept, u)
			continue
		}
		f := u.Recovery
		for _, store := range st.stores {
			if store.entry == u.EntryID && store.source == spanKey(f.SecretSource.Span) {
				at := store.at
				f.StoredField, f.StoredAt = store.key, &at
				if store.project != nil {
					if field, ok := s.securityFields(store.project)[store.key]; ok {
						f.SecurityFields = []analysis.SecurityFieldFact{{StorageKey: store.key, Roles: append([]string{}, field.roles...), Evidence: append([]analysis.Evidence{}, field.evidence...)}}
					}
				}
				break
			}
		}
		if f.RecipientOrigin == analysis.RecipientStoredField && !(f.SecretStrength == analysis.SecretWeak && compared[f.StoredField]) {
			continue
		}
		kept = append(kept, u)
	}
	out.Uses = kept
	s.finishPasswordHashers(out)
	if accountFinishHook != nil {
		accountFinishHook(s)
	}
}

// secretCompared reports a recorded secret_check whose stored getter returns
// the field the secret was written to.
func (s *phpSet) secretCompared(out *analysis.AnalysisReport, store phpSecretStore) bool {
	if store.decl == nil || store.project == nil {
		return false
	}
	f := &phpFlow{set: s, symfony: store.project}
	keys := f.doctrineFieldKeys(store.decl)
	x := s.classIndex()
	for _, u := range out.Uses {
		if u.Authorization == nil {
			continue
		}
		for _, g := range u.Authorization.Guards {
			if g.Kind != analysis.GuardSecret {
				continue
			}
			for _, m := range phpGetterCall.FindAllStringSubmatch(g.Evidence.Text, -1) {
				fn, module := x.methodOf(store.decl, m[1])
				if fn == nil {
					continue
				}
				for _, read := range phpReturnedThisFields(module, fn) {
					if keys[phpText(module, phpField(read, "name"))] == store.key {
						return true
					}
				}
			}
		}
	}
	return false
}
