package langjs

import (
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// Account family for Express (lane decision D-7).
//
// Weak password hashing: a digest of crypto.createHash with md5, sha1, sha224,
// sha256, sha384 or sha512, or of crypto.createHmac with a constant key, whose
// result a credential receives. The digest is followed through one helper
// function that returns it. A credential is established by evidence (D-6):
//
//   - a model attribute whose set accessor stores the digest: Sequelize
//     this.setDataValue(attribute, digest), Mongoose `set` option of a schema
//     field that returns it;
//   - a column that a SQL statement compares with the digest.
//
// bcrypt, argon2, scrypt and crypto.pbkdf2 are not digest operations here, and
// a digest that reaches neither form (a file checksum) records nothing.
var fastDigests = map[string]bool{"md5": true, "sha1": true, "sha224": true, "sha256": true, "sha384": true, "sha512": true}
var sqlSinkMethods = map[string]bool{"query": true, "run": true, "all": true, "get": true, "exec": true, "execute": true, "raw": true}

type digestOp struct {
	module    *sourceModule
	node      *sitter.Node // the whole digest chain
	algorithm string
}

type digestSite struct {
	module *sourceModule
	node   *sitter.Node // where the digest value is used
	basis  string
	detail *sitter.Node // setter call, or the SQL template
	column string
	attr   string
}

// passwordHashCandidates records the D-7 weak hashing claims.
func (s *moduleSet) passwordHashCandidates(out *analysis.AnalysisReport, selected []string) {
	var ops []digestOp
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			if alg, ok := digestChain(m, call); ok {
				ops = append(ops, digestOp{m, call, alg})
			}
		})
	}
	for _, op := range ops {
		for _, site := range s.digestSites(op, selected) {
			s.recordPasswordHash(out, op, site)
		}
	}
}

// digestChain recognizes crypto.createHash(alg).update(...).digest(...) and
// crypto.createHmac(alg, constant).update(...).digest(...).
func digestChain(m *sourceModule, call *sitter.Node) (string, bool) {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Kind() != "member_expression" || memberName(m, fn) != "digest" {
		return "", false
	}
	cur := fn.ChildByFieldName("object")
	sawUpdate := false
	for cur != nil && cur.Kind() == "call_expression" {
		f := cur.ChildByFieldName("function")
		if f == nil {
			return "", false
		}
		if f.Kind() == "member_expression" && memberName(m, f) == "update" {
			sawUpdate = true
			cur = f.ChildByFieldName("object")
			continue
		}
		args := cur.ChildByFieldName("arguments")
		if !sawUpdate || args == nil || args.NamedChildCount() == 0 {
			return "", false
		}
		alg, ok := stringLiteral(args.NamedChild(0), m.src)
		if !ok || !fastDigests[strings.ToLower(alg)] || !cryptoCall(m, cur, f) {
			return "", false
		}
		switch callName(m, f) {
		case "createHash":
			return strings.ToLower(alg), true
		case "createHmac":
			if args.NamedChildCount() < 2 {
				return "", false
			}
			if _, constant := stringLiteral(args.NamedChild(1), m.src); constant {
				return strings.ToLower(alg), true
			}
		}
		return "", false
	}
	return "", false
}

func memberName(m *sourceModule, fn *sitter.Node) string {
	if p := fn.ChildByFieldName("property"); p != nil {
		return p.Utf8Text(m.src)
	}
	return ""
}

func callName(m *sourceModule, f *sitter.Node) string {
	if f.Kind() == "member_expression" {
		return memberName(m, f)
	}
	if f.Kind() == "identifier" {
		if imp, ok := m.imports[f.Utf8Text(m.src)]; ok {
			return imp.name
		}
	}
	return ""
}

// cryptoCall verifies that f names createHash or createHmac of the Node.js
// crypto module.
func cryptoCall(m *sourceModule, call, f *sitter.Node) bool {
	isCrypto := func(module string) bool { return module == "crypto" || module == "node:crypto" }
	switch f.Kind() {
	case "member_expression":
		obj := f.ChildByFieldName("object")
		if obj == nil || obj.Kind() != "identifier" || shadowed(call, obj.Utf8Text(m.src), m.src) {
			return false
		}
		imp, ok := m.imports[obj.Utf8Text(m.src)]
		return ok && isCrypto(imp.module) && (imp.name == "default" || imp.name == "*") && !bindingReassigned(m, obj.Utf8Text(m.src))
	case "identifier":
		imp, ok := m.imports[f.Utf8Text(m.src)]
		return ok && isCrypto(imp.module) && (imp.name == "createHash" || imp.name == "createHmac") && !shadowed(call, f.Utf8Text(m.src), m.src)
	}
	return false
}

// digestSites finds where the digest value reaches a credential: the digest
// chain itself, or a call of the one helper function that returns it.
func (s *moduleSet) digestSites(op digestOp, selected []string) []digestSite {
	sites := []digestSite{}
	use := func(m *sourceModule, node *sitter.Node) {
		if site, ok := s.credentialSite(m, node); ok {
			sites = append(sites, site)
		}
	}
	use(op.module, op.node)
	helper := enclosingFunction(op.node)
	if helper == nil || !returnsNode(helper, op.node) {
		return sites
	}
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn := call.ChildByFieldName("function")
			if fn == nil || (fn.Kind() != "identifier" && fn.Kind() != "member_expression") {
				return
			}
			if shadowed(call, strings.Split(fn.Utf8Text(m.src), ".")[0], m.src) {
				return
			}
			target, node := s.resolve(m, fn.Utf8Text(m.src))
			if target == nil || node == nil || target.file != op.module.file || node.StartByte() != helper.StartByte() {
				return
			}
			use(m, call)
		})
	}
	return sites
}

// returnsNode reports whether fn's value is n: an arrow with n as its
// expression body, or a block whose return statement returns n.
func returnsNode(fn, n *sitter.Node) bool {
	body := fn.ChildByFieldName("body")
	if body == nil {
		return false
	}
	if body.StartByte() == n.StartByte() && body.EndByte() == n.EndByte() {
		return true
	}
	found := false
	var walk func(*sitter.Node)
	walk = func(x *sitter.Node) {
		if x == nil || found || (x != body && isFunction(x)) {
			return
		}
		if x.Kind() == "return_statement" && x.NamedChildCount() == 1 {
			if v := unwrapTS(x.NamedChild(0)); v != nil && v.StartByte() == n.StartByte() && v.EndByte() == n.EndByte() {
				found = true
			}
		}
		for i := uint(0); i < x.NamedChildCount(); i++ {
			walk(x.NamedChild(i))
		}
	}
	walk(body)
	return found
}

// credentialSite classifies the place a digest value is used.
func (s *moduleSet) credentialSite(m *sourceModule, node *sitter.Node) (digestSite, bool) {
	for p := node.Parent(); p != nil; p = p.Parent() {
		switch p.Kind() {
		case "call_expression":
			fn, args := p.ChildByFieldName("function"), p.ChildByFieldName("arguments")
			if fn != nil && fn.Kind() == "member_expression" && memberName(m, fn) == "setDataValue" && args != nil && args.NamedChildCount() == 2 &&
				args.NamedChild(1).StartByte() <= node.StartByte() && node.EndByte() <= args.NamedChild(1).EndByte() {
				if attr, ok := stringLiteral(args.NamedChild(0), m.src); ok {
					return digestSite{module: m, node: node, basis: analysis.BasisCredentialField, detail: p, attr: attr}, true
				}
			}
		case "pair":
			// A Mongoose schema field's `set` option that returns the digest.
			if key := p.ChildByFieldName("key"); key != nil && key.Utf8Text(m.src) == "set" && mongooseSchemaField(m, p) {
				if attr := schemaFieldName(m, p); attr != "" {
					return digestSite{module: m, node: node, basis: analysis.BasisCredentialField, detail: p, attr: attr}, true
				}
			}
		case "template_string":
			if column, ok := compareColumn(m, p, node); ok && sqlStatement(m, p) {
				return digestSite{module: m, node: node, basis: analysis.BasisSQLCredentialColumn, detail: p, column: column}, true
			}
			return digestSite{}, false
		}
	}
	return digestSite{}, false
}

// mongooseSchemaField reports whether pair is the `set` option of a field
// object inside new mongoose.Schema(...).
func mongooseSchemaField(m *sourceModule, pair *sitter.Node) bool {
	for p := pair.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "new_expression" {
			ctor := p.ChildByFieldName("constructor")
			if ctor == nil {
				return false
			}
			name := ctor.Utf8Text(m.src)
			if ctor.Kind() == "member_expression" {
				obj := ctor.ChildByFieldName("object")
				imp, ok := m.imports[obj.Utf8Text(m.src)]
				return ok && imp.module == "mongoose" && memberName(m, ctor) == "Schema"
			}
			imp, ok := m.imports[name]
			return ok && imp.module == "mongoose" && imp.name == "Schema"
		}
	}
	return false
}

// schemaFieldName returns the property name of the field that holds a `set`
// option pair.
func schemaFieldName(m *sourceModule, pair *sitter.Node) string {
	obj := pair.Parent()
	if obj == nil || obj.Kind() != "object" {
		return ""
	}
	field := obj.Parent()
	if field != nil && field.Kind() == "pair" {
		if key := field.ChildByFieldName("key"); key != nil {
			return strings.Trim(key.Utf8Text(m.src), `"'`)
		}
	}
	return ""
}

// compareColumn returns the column that the static text before the
// substitution holding node compares: `<column> = '${...}'`.
func compareColumn(m *sourceModule, tmpl, node *sitter.Node) (string, bool) {
	var before strings.Builder
	for i := uint(0); i < tmpl.ChildCount(); i++ {
		c := tmpl.Child(i)
		if c.StartByte() <= node.StartByte() && node.EndByte() <= c.EndByte() {
			break
		}
		before.WriteString(c.Utf8Text(m.src))
	}
	text := strings.TrimRight(strings.TrimSuffix(strings.TrimRight(before.String(), " \t\n"), "'"), " \t\n")
	if !strings.HasSuffix(text, "=") {
		return "", false
	}
	text = strings.TrimRight(strings.TrimSuffix(text, "="), " \t\n")
	end := len(text)
	start := end
	for start > 0 && (text[start-1] == '_' || text[start-1] == '.' || text[start-1] >= '0' && text[start-1] <= '9' || text[start-1] >= 'a' && text[start-1] <= 'z' || text[start-1] >= 'A' && text[start-1] <= 'Z') {
		start--
	}
	if start == end {
		return "", false
	}
	return text[start:end], true
}

// sqlStatement reports whether a template string is the statement argument of
// a query-running call.
func sqlStatement(m *sourceModule, tmpl *sitter.Node) bool {
	p := tmpl.Parent()
	for p != nil && p.Kind() != "arguments" {
		p = p.Parent()
	}
	if p == nil || p.Parent() == nil || p.Parent().Kind() != "call_expression" || p.NamedChild(0) == nil || p.NamedChild(0).StartByte() > tmpl.StartByte() {
		return false
	}
	fn := p.Parent().ChildByFieldName("function")
	return fn != nil && fn.Kind() == "member_expression" && sqlSinkMethods[memberName(m, fn)]
}

func (s *moduleSet) recordPasswordHash(out *analysis.AnalysisReport, op digestOp, site digestSite) {
	if site.attr != "" {
		if s.credentialAttrs == nil {
			s.credentialAttrs = map[string]bool{}
		}
		s.credentialAttrs[site.attr] = true
	}
	var entry *analysis.EntryPoint
	if entries := s.entriesFor(out, site.module, site.node); len(entries) > 0 {
		entry = &entries[0]
	} else {
		var http []analysis.EntryPoint
		for _, e := range out.Entries {
			if e.Kind == "http" {
				http = append(http, e)
			}
		}
		sort.Slice(http, func(i, j int) bool { return http[i].ID < http[j].ID })
		if len(http) == 0 {
			out.Gaps = append(out.Gaps, analysis.Gap{Kind: "password_hash_entry_missing", Detail: "a fast digest reaches a credential and the project has no HTTP entry to report it under", At: op.module.evidence("digest_operation", op.node).Span})
			return
		}
		entry = &http[0]
	}
	sink := op.module.evidence(analysis.PasswordHashKind, op.node)
	operation := op.module.evidence("digest_operation", op.node)
	basis := site.module.evidence("password_basis", site.detail)
	basisEvidence := []analysis.Evidence{basis}
	var fields []analysis.SecurityFieldFact
	if site.attr != "" {
		fields = []analysis.SecurityFieldFact{{StorageKey: "js-attribute:" + site.attr, Roles: []string{"credential"}, Evidence: []analysis.Evidence{basis}}}
	} else {
		fields = []analysis.SecurityFieldFact{{StorageKey: "js-sql-column:" + site.column, Roles: []string{"credential"}, Evidence: []analysis.Evidence{basis}}}
	}
	facts := &analysis.PasswordHashFacts{Algorithm: op.algorithm, Basis: site.basis, BasisEvidence: basisEvidence, Salted: "no", Iterated: "no", SecurityFields: fields}
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: entry.ID, Kind: analysis.PasswordHashKind, Sink: sink, PasswordHash: facts,
		APIModel:   analysispacks.AccountContract(analysispacks.NodePasswordDigest),
		Gaps:       []analysis.Gap{},
		Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "password_hash", Required: analysispacks.AccountRoles(analysis.PasswordHashKind),
			Scope: "One fast digest operation and the evidence that its result is a stored or compared password.",
			Evidence: map[string][]analysis.Evidence{
				"digest_operation": {operation},
				"password_basis":   basisEvidence,
				"sink_binding":     {asEvidenceKind(sink, "sink_binding")},
			},
			Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
		},
	})
}
