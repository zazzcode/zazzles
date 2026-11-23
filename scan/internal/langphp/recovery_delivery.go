package langphp

import (
	"fmt"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Recovery-secret delivery. A generated secret that reaches mail content is
// recorded with the origin of its recipient and the checks that tied the
// recipient to the account.

// phpSecret is the generated secret a value derives from.
// bits is negative when the entropy cannot be computed from literal arguments.
// encoding is hex or base64 when a later substr can scale the bit count.
type phpSecret struct {
	source   analysis.Evidence
	strength string // csprng | weak
	bits     float64
	encoding string
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
	// paramUses are request values bound to an array-typed parameter. They
	// count only where no iteration or spread of the same value is recorded.
	paramUses map[string]map[string]analysis.Evidence
	stores    []phpSecretStore
	sends     []phpMailSend // every modeled send, in walk order
	plain     *plainAccountSQL
}

func (s *phpSet) accountState() *phpAccountState {
	if s.account == nil {
		s.account = &phpAccountState{mails: map[int]*phpMail{}, lookups: map[string][]phpAccountLookup{}, shapeUses: map[string]map[string]analysis.Evidence{},
			paramUses: map[string]map[string]analysis.Evidence{}}
	}
	return s.account
}

func depKey(d phpDep) string {
	return spanKey(d.dep.Source.Span)
}

// Secret sources: a CSPRNG, or a predictable value. A value computed from a
// secret keeps its source and strength. Bits change only for the modeled
// transforms, and only on a copy of the secret.
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
		fresh := false
		switch {
		case csprngFunctions[name]:
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG, bits: f.csprngBits(name, nodes)}
			fresh = true
		case weakFunctions[name]:
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretWeak, bits: -1}
			fresh = true
		case name == "mail":
			f.phpMailCall(n, nodes, values)
		}
		f.plainAccountCall(n, values)
		f.plainDigest(n)
		v = f.digestCall(n, name, nodes, v)
		if !fresh {
			v = f.adjustSecret(name, nodes, v)
		}
	case "member_call_expression":
		f.plainAccountCall(n, values)
	case "scoped_call_expression":
		class := strings.TrimPrefix(f.set.classIndex().qualify(f.module, phpText(f.module, phpField(n, "scope")), n.StartByte()), `\`)
		method := strings.ToLower(phpText(f.module, phpField(n, "name")))
		switch {
		case strings.EqualFold(class, `Symfony\Component\Uid\Uuid`) && method == "v4":
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG, bits: 122}
		case strings.EqualFold(class, `Symfony\Component\String\ByteString`) && method == "fromrandom":
			v.secret = &phpSecret{source: f.module.evidence("secret_source", n), strength: analysis.SecretCSPRNG, bits: f.fromRandomBits(nodes)}
		}
	}
	return v
}

// adjustSecret copies a joined secret and applies one modeled transform.
// An unrecognized call leaves the bits unknown. The shared secret is not written.
func (f *phpFlow) adjustSecret(name string, nodes []*sitter.Node, v phpValue) phpValue {
	if v.secret == nil {
		return v
	}
	sec := *v.secret
	switch name {
	case "bin2hex":
		sec.encoding = "hex"
	case "base64_encode":
		sec.encoding = "base64"
	case "md5":
		sec.bits = capBits(sec.bits, 128)
		sec.encoding = f.digestEncoding(nodes, 1)
	case "sha1":
		sec.bits = capBits(sec.bits, 160)
		sec.encoding = f.digestEncoding(nodes, 1)
	case "hash", "hash_hmac":
		algo, ok := "", false
		if len(nodes) > 0 {
			algo, ok = phpStringLiteral(f.module, nodes[0])
		}
		if !ok {
			sec.bits = -1
		} else if out, known := hashOutputBits(algo); known {
			sec.bits = capBits(sec.bits, out)
		}
		binary := 2
		if name == "hash_hmac" {
			binary = 3
		}
		sec.encoding = f.digestEncoding(nodes, binary)
	case "substr":
		length, ok := literalInt(f.module, nthNode(nodes, 2))
		scale := 4.0
		if sec.encoding == "base64" {
			scale = 6
		}
		if ok && length >= 0 && (sec.encoding == "hex" || sec.encoding == "base64") {
			sec.bits = capBits(sec.bits, float64(length)*scale)
		} else {
			sec.bits = -1
		}
		sec.encoding = ""
	default:
		sec.bits = -1
		sec.encoding = ""
	}
	v.secret = &sec
	return v
}

// digestEncoding is "hex" for a digest function's default output. The
// argument at binary asks for raw bytes, and then a later substr no longer
// counts four bits a character.
func (f *phpFlow) digestEncoding(nodes []*sitter.Node, binary int) string {
	if n := nthNode(nodes, binary); n != nil && !strings.EqualFold(phpText(f.module, n), "false") {
		return ""
	}
	return "hex"
}

func (f *phpFlow) csprngBits(name string, nodes []*sitter.Node) float64 {
	switch name {
	case "random_bytes", "openssl_random_pseudo_bytes":
		n, ok := literalInt(f.module, nthNode(nodes, 0))
		if !ok || n < 0 {
			return -1
		}
		return float64(8 * n)
	case "random_int":
		a, aok := literalInt(f.module, nthNode(nodes, 0))
		b, bok := literalInt(f.module, nthNode(nodes, 1))
		if !aok || !bok || b < a {
			return -1
		}
		span := b - a + 1
		if span <= 1 {
			return 0
		}
		return floorTenths(math.Log2(float64(span)))
	}
	return -1
}

func (f *phpFlow) fromRandomBits(nodes []*sitter.Node) float64 {
	n, ok := literalInt(f.module, nthNode(nodes, 0))
	if !ok || n < 0 {
		return -1
	}
	alphabet := 62
	if len(nodes) > 1 {
		text, ok := phpStringLiteral(f.module, nodes[1])
		if !ok {
			return -1
		}
		alphabet = len(text)
	}
	if alphabet <= 1 {
		return 0
	}
	return floorTenths(float64(n) * math.Log2(float64(alphabet)))
}

func hashOutputBits(algo string) (float64, bool) {
	switch strings.ToLower(algo) {
	case "md5":
		return 128, true
	case "sha1":
		return 160, true
	case "sha256":
		return 256, true
	case "sha384":
		return 384, true
	case "sha512":
		return 512, true
	}
	return 0, false
}

func capBits(in, out float64) float64 {
	if in < 0 {
		return -1
	}
	if out < in {
		return out
	}
	return in
}

func floorTenths(v float64) float64 {
	return math.Floor(v*10) / 10
}

func literalInt(m *phpModule, n *sitter.Node) (int, bool) {
	if n == nil {
		return 0, false
	}
	for n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	if n.Kind() != "integer" {
		return 0, false
	}
	v, err := strconv.Atoi(strings.TrimSpace(phpText(m, n)))
	return v, err == nil
}

func nthNode(nodes []*sitter.Node, i int) *sitter.Node {
	if i < 0 || i >= len(nodes) {
		return nil
	}
	return nodes[i]
}

func secretBitsOf(s *phpSecret) analysis.SecretBits {
	if s == nil || s.bits < 0 {
		return analysis.SecretBits{}
	}
	return analysis.SecretBits{Known: true, Bits: s.bits}
}

// noteArrayUse records a request value used as an array: iterated by
// foreach or spread into a call.
func (f *phpFlow) noteArrayUse(at *sitter.Node, v phpValue) {
	f.noteShapeUse(f.set.accountState().shapeUses, at, v)
}

// noteArrayParameter records a request value passed to an array-typed
// parameter.
func (f *phpFlow) noteArrayParameter(at *sitter.Node, v phpValue) {
	f.noteShapeUse(f.set.accountState().paramUses, at, v)
}

func (f *phpFlow) noteShapeUse(uses map[string]map[string]analysis.Evidence, at *sitter.Node, v phpValue) {
	if f.entry.ID == "" {
		return
	}
	for _, d := range phpInputDeps([]phpValue{v}) {
		if uses[f.entry.ID] == nil {
			uses[f.entry.ID] = map[string]analysis.Evidence{}
		}
		if _, ok := uses[f.entry.ID][depKey(d)]; !ok {
			uses[f.entry.ID][depKey(d)] = f.module.evidence("array_use", at)
		}
	}
}

// phpArrayParameter reports a parameter declared `array` or `?array`.
func phpArrayParameter(m *phpModule, p *sitter.Node) bool {
	return strings.EqualFold(strings.TrimPrefix(strings.TrimSpace(phpText(m, phpField(p, "type"))), "?"), "array")
}

// noteAccountLookup records a finder's request criteria for the recipient
// check, with the first criterion read through a literal index.
func (f *phpFlow) noteAccountLookup(n *sitter.Node, deps []phpDep) {
	if args := phpArgs(n); len(args) > 0 {
		f.noteAccountLookupAt(args[0], deps)
		return
	}
	f.noteAccountLookupAt(nil, deps)
}

// noteAccountLookupAt records a lookup whose criteria are the given node.
func (f *phpFlow) noteAccountLookupAt(criteria *sitter.Node, deps []phpDep) {
	if f.entry.ID == "" || len(deps) == 0 {
		return
	}
	l := phpAccountLookup{sources: map[string]bool{}}
	for _, d := range deps {
		l.sources[depKey(d)] = true
	}
	if criteria != nil {
		phpWalk(criteria, func(c *sitter.Node) {
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

// noteRecovery records a send whose content carries a secret, with the
// origin of its recipient and the checks that tied it to the account.
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
	recipient := s.recipients[0]
	var deps []phpDep
	for _, r := range s.recipients {
		if d := phpInputDeps([]phpValue{r.value}); len(d) > 0 {
			recipient, deps = r, d
			break
		}
	}
	facts := &analysis.RecoveryFacts{SecretSource: secret.source, SecretStrength: secret.strength, SecretBits: secretBitsOf(secret), Recipient: recipient.at, Content: content.at,
		MailContract: s.contract, SecurityFields: []analysis.SecurityFieldFact{}}
	f.recipientFacts(facts, deps)
	f.emitRecovery(s, facts, deps)
}

// recipientFacts fills the recipient origin, validation and count of a
// recovery record from the request dependencies of its recipient.
func (f *phpFlow) recipientFacts(facts *analysis.RecoveryFacts, deps []phpDep) {
	if len(deps) == 0 {
		facts.RecipientOrigin, facts.RecipientValidated, facts.RecipientCount = analysis.RecipientStoredField, analysis.RecipientFull, analysis.RecipientCountOne
		return
	}
	st := f.set.accountState()
	facts.RecipientOrigin = analysis.RecipientRequestValue
	use := firstShapeUse(st.shapeUses[f.entry.ID], deps)
	if use == nil {
		use = firstShapeUse(st.paramUses[f.entry.ID], deps)
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

// firstShapeUse is the recorded array use of the first dependency that has
// one.
func firstShapeUse(uses map[string]analysis.Evidence, deps []phpDep) *analysis.Evidence {
	for _, d := range deps {
		if e, ok := uses[depKey(d)]; ok {
			return &e
		}
	}
	return nil
}

func (f *phpFlow) emitRecovery(s phpMailSend, facts *analysis.RecoveryFacts, deps []phpDep) {
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
				"secret_source":  {facts.SecretSource},
				"mail_recipient": {facts.Recipient},
				"mail_content":   {facts.Content},
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
			s.addRecoverySecretRole(store.project, store.key, store.at)
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
