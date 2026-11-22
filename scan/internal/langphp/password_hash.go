package langphp

import (
	"fmt"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Weak password hashing. A fast digest is recorded only when evidence says
// its input is a password: a census credential field, a password-hasher class
// or the security configuration.

const (
	symfonyLegacyPasswordHasher = `Symfony\Component\PasswordHasher\LegacyPasswordHasherInterface`
)

// phpDigest marks a value computed by one fast digest call.
type phpDigest struct {
	algorithm string
	at        analysis.Evidence
	salted    string
	unmodeled bool
}

// digestAlgorithm returns the algorithm of a digest call, or "", and whether
// the contract leaves its parameters unmodeled.
func digestAlgorithm(m *phpModule, name string, nodes []*sitter.Node) (string, bool) {
	algorithm := ""
	switch name {
	case "md5", "sha1", "crc32":
		algorithm = name
	case "hash", "hash_hmac":
		if len(nodes) > 0 {
			if algo, ok := phpStringLiteral(m, nodes[0]); ok && algo != "" {
				algorithm = strings.ToLower(algo)
			}
		}
	case "crypt":
		algorithm = "crypt"
	case "hash_pbkdf2":
		algorithm = "pbkdf2"
	}
	return algorithm, algorithm != "" && analysispacks.PasswordDigestUnmodeled(algorithm)
}

// digestInput is the argument a digest hashes.
func digestInput(name string, nodes []*sitter.Node) *sitter.Node {
	i := 0
	if name == "hash" || name == "hash_hmac" || name == "hash_pbkdf2" {
		i = 1
	}
	if i < len(nodes) {
		return nodes[i]
	}
	return nil
}

// phpSalted is yes when the digest input concatenates the password with
// another non-literal value.
func phpSalted(m *phpModule, n *sitter.Node) string {
	for n != nil && n.Kind() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	if n == nil || n.Kind() != "binary_expression" || phpOperator(m, n) != "." {
		return "no"
	}
	count := 0
	var walk func(c *sitter.Node)
	walk = func(c *sitter.Node) {
		for c != nil && c.Kind() == "parenthesized_expression" && c.NamedChildCount() == 1 {
			c = c.NamedChild(0)
		}
		if c == nil {
			return
		}
		if c.Kind() == "binary_expression" && phpOperator(m, c) == "." {
			walk(phpField(c, "left"))
			walk(phpField(c, "right"))
			return
		}
		if _, ok := phpStringLiteral(m, c); !ok {
			count++
		}
	}
	walk(n)
	if count >= 2 {
		return "yes"
	}
	return "no"
}

// digestCall marks the result of a digest call (contract
// api.php-password-digest-v1). md5_file and the adaptive hashers are not
// digests here.
func (f *phpFlow) digestCall(n *sitter.Node, name string, nodes []*sitter.Node, v phpValue) phpValue {
	algorithm, unmodeled := digestAlgorithm(f.module, name, nodes)
	if algorithm == "" {
		return v
	}
	v.digest = &phpDigest{algorithm: algorithm, at: f.module.evidence(analysis.PasswordHashKind, n), salted: phpSalted(f.module, digestInput(name, nodes)), unmodeled: unmodeled}
	return v
}

// noteDigestStore records a digest written to a census credential field.
func (f *phpFlow) noteDigestStore(key string, v phpValue, at *sitter.Node) {
	if v.digest == nil || f.report == nil || at == nil {
		return
	}
	fact, ok := f.censusFact(key)
	if !ok || !slices.Contains(fact.Roles, analysis.RoleCredential) {
		return
	}
	basis := []analysis.Evidence{f.authzSink(at)}
	for i, role := range fact.Roles {
		if role == analysis.RoleCredential && i < len(fact.Evidence) {
			basis = append(basis, fact.Evidence[i])
		}
	}
	d := v.digest
	facts := &analysis.PasswordHashFacts{Algorithm: d.algorithm, Basis: analysis.BasisCredentialField, BasisEvidence: basis, Salted: d.salted, Iterated: "no",
		SecurityFields: []analysis.SecurityFieldFact{fact}}
	emitPasswordHash(f.report, f.entry.ID, f.invocation.ID, d, facts, f.context, f.gaps)
}

func emitPasswordHash(out *analysis.AnalysisReport, entryID, invocationID string, d *phpDigest, facts *analysis.PasswordHashFacts, context []analysis.Evidence, gaps []analysis.Gap) {
	sink := d.at
	id := fmt.Sprintf("use:%s:%s:%d:%s", invocationID, sink.Span.File, sink.Span.StartByte, analysis.PasswordHashKind)
	for _, u := range out.Uses {
		if u.ID == id {
			return
		}
	}
	blockers := []analysis.Gap{}
	if d.unmodeled {
		blockers = append(blockers, analysis.Gap{Kind: analysis.PasswordDigestUnmodeled, Detail: d.algorithm + " parameters are not modeled.", At: sink.Span})
	}
	if facts.SecurityFields == nil {
		facts.SecurityFields = []analysis.SecurityFieldFact{}
	}
	binding := sink
	binding.Kind = "sink_binding"
	out.Uses = append(out.Uses, analysis.CandidateUse{
		ID: id, EntryID: entryID, InvocationContextID: invocationID,
		Kind: analysis.PasswordHashKind, Sink: sink, Dependencies: []analysis.Dependency{},
		Context: phpDedupeEvidence(context), Gaps: append([]analysis.Gap{}, gaps...),
		Assessment:   analysis.Assessment{Status: "not_run"},
		PasswordHash: facts,
		APIModel:     analysispacks.AccountContract(analysispacks.PHPPasswordDigest),
		Completeness: &analysis.Completeness{
			ClaimKind: "password_hash",
			Required:  []string{"digest_operation", "password_basis"},
			Scope:     "One fast digest and the evidence that its input is a password.",
			Evidence: map[string][]analysis.Evidence{
				"digest_operation": {sink},
				"password_basis":   facts.BasisEvidence,
				"sink_binding":     {binding},
			},
			Blockers: blockers,
			Coverage: []analysis.Gap{},
		},
	})
}

// finishPasswordHashers records the digests a hasher class returns and the
// password_hashers lines that select a fast algorithm or such a class. The
// records belong to the firewall's form-login entry, where Symfony verifies
// passwords with the selected hasher. A project whose login route does not
// resolve (form_login defaults, a custom authenticator, http_basic) anchors
// them to its first entry: the claim needs no HTTP entry of its own.
func (s *phpSet) finishPasswordHashers(out *analysis.AnalysisReport) {
	for _, p := range s.symfony {
		entryID, invocationID := s.loginEntry(out, p)
		if entryID == "" {
			entryID, invocationID = s.projectEntry(out, p)
		}
		if entryID == "" {
			continue
		}
		x := s.classIndex()
		hashers := map[string]*phpDigest{}
		for _, decl := range s.projectClasses(p) {
			interfaces := x.interfacesOf(decl)
			if !interfaces[strings.ToLower(symfonyPasswordHasher)] && !interfaces[strings.ToLower(symfonyLegacyPasswordHasher)] {
				continue
			}
			fn, module := x.methodOf(decl, "hash")
			if fn == nil {
				continue
			}
			phpWalk(phpField(fn, "body"), func(c *sitter.Node) {
				if c.Kind() != "return_statement" || c.NamedChildCount() == 0 || hashers[decl.fqn] != nil {
					return
				}
				call := c.NamedChild(0)
				if call.Kind() != "function_call_expression" {
					return
				}
				name := strings.ToLower(strings.TrimPrefix(phpText(module, phpField(call, "function")), `\`))
				nodes := phpArgs(call)
				algorithm, unmodeled := digestAlgorithm(module, name, nodes)
				if algorithm == "" {
					return
				}
				d := &phpDigest{algorithm: algorithm, at: module.evidence(analysis.PasswordHashKind, call), salted: phpSalted(module, digestInput(name, nodes)), unmodeled: unmodeled}
				hashers[decl.fqn] = d
				basis := []analysis.Evidence{module.evidence(analysis.BasisHasherClass, fn)}
				emitPasswordHash(out, entryID, invocationID, d, &analysis.PasswordHashFacts{Algorithm: algorithm, Basis: analysis.BasisHasherClass, BasisEvidence: basis, Salted: d.salted, Iterated: "no", HasherClass: decl.fqn}, nil, nil)
			})
		}
		for _, h := range p.security(s).passwordHashers() {
			var d *phpDigest
			class := ""
			switch {
			case h.id != "":
				hd := hashers[strings.TrimPrefix(h.id, `\`)]
				if hd == nil {
					continue
				}
				class = strings.TrimPrefix(h.id, `\`)
				d = &phpDigest{algorithm: hd.algorithm, at: h.at, salted: "no", unmodeled: hd.unmodeled}
			case analysispacks.ConfiguredPasswordDigest(h.algorithm):
				d = &phpDigest{algorithm: h.algorithm, at: h.at, salted: "no"}
			default:
				continue
			}
			emitPasswordHash(out, entryID, invocationID, d, &analysis.PasswordHashFacts{Algorithm: d.algorithm, Basis: analysis.BasisConfiguration, BasisEvidence: []analysis.Evidence{h.at}, Salted: "no", Iterated: "no", HasherClass: class}, nil, nil)
		}
	}
}

// loginEntry is the POST (else ANY) entry of the route a firewall's
// form_login or json_login checks: check_path, else login_path.
func (s *phpSet) loginEntry(out *analysis.AnalysisReport, p *symfonyProject) (string, string) {
	name := p.security(s).loginRoute()
	if name == "" {
		return "", ""
	}
	path := ""
	for _, r := range p.routes(s) {
		if r.name == name || r.path == name {
			path = r.path
			break
		}
	}
	if path == "" {
		return "", ""
	}
	for _, verb := range []string{"POST", "ANY"} {
		for _, e := range out.Entries {
			if e.Name == verb+" "+path {
				for _, c := range out.InvocationContexts {
					if c.EntryID == e.ID {
						return e.ID, c.ID
					}
				}
			}
		}
	}
	return "", ""
}

// projectEntry is the first entry of a project, in report order, with an
// invocation context.
func (s *phpSet) projectEntry(out *analysis.AnalysisReport, p *symfonyProject) (string, string) {
	for _, e := range out.Entries {
		file := e.Location.Span.File
		if p.root != "" && p.root != "." && file != p.root && !strings.HasPrefix(file, p.root+"/") {
			continue
		}
		for _, c := range out.InvocationContexts {
			if c.EntryID == e.ID {
				return e.ID, c.ID
			}
		}
	}
	return "", ""
}
