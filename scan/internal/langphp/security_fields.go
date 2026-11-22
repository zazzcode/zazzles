package langphp

import (
	"slices"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Framework contracts the census reads (branch 1 D-4). Each role comes from
// what the framework or the code does with a field, never from its name.
const (
	symfonyUserInterface         = `Symfony\Component\Security\Core\User\UserInterface`
	symfonyPasswordAuthenticated = `Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface`
	symfonyUserPasswordHasher    = `Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface`
	symfonyPasswordHasher        = `Symfony\Component\PasswordHasher\PasswordHasherInterface`
)

// securityNameHints is the closed hint list of D-4: property names lower-cased
// with separators removed. A hint never sets another role.
var securityNameHints = map[string]bool{
	"isadmin": true, "admin": true, "issuperuser": true, "superuser": true, "isstaff": true, "role": true, "roles": true,
	"permissions": true, "privileges": true, "password": true, "passwordhash": true, "apikey": true, "token": true,
	"resettoken": true, "verified": true, "isverified": true, "balance": true, "credit": true, "ownerid": true,
	"userid": true, "tenantid": true,
}

// securityField is one stored field of the census (lane contract section 2.3).
type securityField struct {
	storageKey string              // "php-sql:<table>.<column>", as doctrine_storage.go builds it
	roles      []string            // sorted, from the closed list
	evidence   []analysis.Evidence // one per role, at the establishing source
}

type phpSecurityCensus struct {
	fields map[string]securityField
	gaps   []analysis.Gap
}

// securityFields returns the census for one project. Deterministic; computed
// once per phpSet.
func (s *phpSet) securityFields(p *symfonyProject) map[string]securityField {
	return s.securityCensus(p).fields
}

// securityGaps returns the census gaps of one project (D-5).
func (s *phpSet) securityGaps(p *symfonyProject) []analysis.Gap {
	return s.securityCensus(p).gaps
}

func (s *phpSet) securityCensus(p *symfonyProject) *phpSecurityCensus {
	if s.census == nil {
		s.census = map[*symfonyProject]*phpSecurityCensus{}
	}
	if c := s.census[p]; c != nil {
		return c
	}
	c := &phpSecurityCensus{fields: map[string]securityField{}}
	s.census[p] = c
	if p == nil {
		return c
	}
	f := &phpFlow{set: s, symfony: p}
	x := s.classIndex()
	found := map[string]map[string]analysis.Evidence{} // key -> role -> first evidence
	add := func(key, role string, e analysis.Evidence) {
		if key == "" {
			return
		}
		if found[key] == nil {
			found[key] = map[string]analysis.Evidence{}
		}
		if _, ok := found[key][role]; !ok {
			e.Kind = role
			found[key][role] = e
		}
	}
	security := p.security(s)
	users := 0
	for _, decl := range s.projectClasses(p) {
		keys := f.doctrineFieldKeys(decl)
		if len(keys) == 0 {
			continue
		}
		m := decl.module
		for _, name := range security.sortedProviders() {
			provider := security.providers[name]
			if strings.EqualFold(strings.TrimPrefix(provider.class, `\`), decl.fqn) {
				add(keys[provider.property], analysis.RoleLoginIdentifier, provider.at)
			}
		}
		interfaces := x.interfacesOf(decl)
		if interfaces[strings.ToLower(symfonyPasswordAuthenticated)] {
			if fn, module := x.methodOf(decl, "getPassword"); fn != nil {
				for _, read := range phpReturnedThisFields(module, fn) {
					add(keys[phpText(module, phpField(read, "name"))], analysis.RoleCredential, module.evidence(analysis.RoleCredential, read))
				}
			}
		}
		if interfaces[strings.ToLower(symfonyUserInterface)] {
			users++
			for _, method := range []string{"getUserIdentifier", "getUsername"} {
				if fn, module := x.methodOf(decl, method); fn != nil {
					for _, read := range phpReturnedThisFields(module, fn) {
						add(keys[phpText(module, phpField(read, "name"))], analysis.RoleLoginIdentifier, module.evidence(analysis.RoleLoginIdentifier, read))
					}
				}
			}
			roleFields := map[string]bool{}
			if fn, module := x.methodOf(decl, "getRoles"); fn != nil {
				if s.phpUnfollowedCall(module, phpField(fn, "body")) {
					c.gaps = append(c.gaps, analysis.Gap{Kind: analysis.SecurityFieldsUnresolved, Detail: "getRoles() reads its value through a call the census does not follow.", At: module.evidence("method", fn).Span})
				}
				for _, read := range phpThisFieldReads(module, phpField(fn, "body")) {
					name := phpText(module, phpField(read, "name"))
					if keys[name] != "" {
						roleFields[name] = true
						add(keys[name], analysis.RoleSource, module.evidence(analysis.RoleSource, read))
					}
				}
			}
			// One step: a lifecycle callback that writes a role source reads
			// the fields that compute it.
			for _, fn := range s.lifecycleCallbacks(f, decl) {
				body := phpField(fn, "body")
				if !slices.ContainsFunc(phpThisFieldWrites(m, body), func(n string) bool { return roleFields[n] }) {
					continue
				}
				for _, read := range phpThisFieldReads(m, body) {
					add(keys[phpText(m, phpField(read, "name"))], analysis.RoleSource, m.evidence(analysis.RoleSource, read))
				}
			}
		}
		for _, field := range sortedTwigFields(keys) {
			if securityNameHints[strings.NewReplacer("_", "", "-", "").Replace(strings.ToLower(field))] {
				add(keys[field], analysis.RoleNameHint, m.evidence(analysis.RoleNameHint, phpPropertyElement(m, symfonyProperties(decl)[field], field)))
			}
		}
	}
	for _, w := range s.passwordHashWrites(f, p) {
		add(w.key, analysis.RoleCredential, w.at)
	}
	if users == 0 {
		c.gaps = append(c.gaps, analysis.Gap{Kind: analysis.SecurityFieldsUnresolved, Detail: "No class implements the Symfony security UserInterface.", At: p.composerSpan})
	}
	for key, roles := range found {
		field := securityField{storageKey: key}
		for _, role := range sortedTwigFields(roles) {
			field.roles = append(field.roles, role)
			field.evidence = append(field.evidence, roles[role])
		}
		c.fields[key] = field
	}
	return c
}

// projectClasses lists the project's classes in stable order.
func (s *phpSet) projectClasses(p *symfonyProject) []*phpClassDecl {
	x := s.classIndex()
	var out []*phpClassDecl
	for _, name := range sortedTwigFields(x.byName) {
		for _, d := range x.byName[name] {
			if d.kind == "class" && s.symfonyProjectOf(d.module.file) == p {
				out = append(out, d)
			}
		}
	}
	return out
}

// interfacesOf returns the lower-cased qualified interfaces a class declares,
// through its in-repository extends chain.
func (x *phpClassIndex) interfacesOf(d *phpClassDecl) map[string]bool {
	out := map[string]bool{}
	for depth := 0; d != nil && depth <= phpClassDepth; depth++ {
		for i := uint(0); i < d.node.NamedChildCount(); i++ {
			clause := d.node.NamedChild(i)
			if clause.Kind() != "class_interface_clause" {
				continue
			}
			for j := uint(0); j < clause.NamedChildCount(); j++ {
				name := clause.NamedChild(j)
				out[strings.ToLower(x.qualify(d.module, phpText(d.module, name), name.StartByte()))] = true
			}
		}
		d, _ = x.parentOf(d)
	}
	return out
}

func (x *phpClassIndex) methodOf(d *phpClassDecl, name string) (*sitter.Node, *phpModule) {
	_, fn, m, _ := x.method(d, name)
	if fn == nil || m == nil {
		return nil, nil
	}
	return fn, m
}

// phpReturnedThisFields returns the $this->p reads a method returns directly
// or through a cast.
func phpReturnedThisFields(m *phpModule, fn *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
		if n.Kind() != "return_statement" || n.NamedChildCount() == 0 {
			return
		}
		v := n.NamedChild(0)
		for v != nil && (v.Kind() == "cast_expression" || v.Kind() == "parenthesized_expression") {
			v = v.NamedChild(v.NamedChildCount() - 1)
		}
		if phpThisField(m, v) {
			out = append(out, v)
		}
	})
	return out
}

func phpThisField(m *phpModule, n *sitter.Node) bool {
	return n != nil && n.Kind() == "member_access_expression" && phpVarName(m, phpField(n, "object")) == "this" && phpField(n, "name") != nil && phpField(n, "name").Kind() == "name"
}

// phpThisFieldReads returns every $this->p read in a body, excluding the left
// side of an assignment, in source order.
func phpThisFieldReads(m *phpModule, body *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	phpWalk(body, func(n *sitter.Node) {
		if !phpThisField(m, n) {
			return
		}
		if p := n.Parent(); p != nil && p.Kind() == "assignment_expression" && phpField(p, "left") != nil && phpField(p, "left").Id() == n.Id() {
			return
		}
		out = append(out, n)
	})
	return out
}

// phpThisFieldWrites returns the property names a body assigns on $this.
func phpThisFieldWrites(m *phpModule, body *sitter.Node) []string {
	var out []string
	phpWalk(body, func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" && phpThisField(m, phpField(n, "left")) {
			out = append(out, phpText(m, phpField(phpField(n, "left"), "name")))
		}
	})
	return out
}

// phpUnfollowedCall reports a call in a getRoles() body that the one-step read
// does not follow: a method or static call, or a function declared in the
// project. Builtin array helpers are part of the one step.
func (s *phpSet) phpUnfollowedCall(m *phpModule, body *sitter.Node) bool {
	found := false
	phpWalk(body, func(n *sitter.Node) {
		switch n.Kind() {
		case "member_call_expression", "nullsafe_member_call_expression", "scoped_call_expression":
			found = true
		case "function_call_expression":
			if _, local := m.funcs[phpText(m, phpCallee(n))]; local {
				found = true
			}
		}
	})
	return found
}

// lifecycleCallbacks returns the class's #[ORM\PrePersist] and #[ORM\PreUpdate]
// methods, or their docblock forms (Doctrine lifecycle callbacks).
func (s *phpSet) lifecycleCallbacks(f *phpFlow, d *phpClassDecl) []*sitter.Node {
	var out []*sitter.Node
	body := phpField(d.node, "body")
	m := d.module
	for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
		method := body.NamedChild(i)
		if method.Kind() != "method_declaration" {
			continue
		}
		hook := f.symfonyAttribute(m, method, doctrineORM+"PrePersist") != nil || f.symfonyAttribute(m, method, doctrineORM+"PreUpdate") != nil
		if !hook {
			if c := method.PrevNamedSibling(); c != nil && c.Kind() == "comment" {
				text := strings.ToLower(phpText(m, c))
				hook = strings.Contains(text, `@orm\prepersist`) || strings.Contains(text, `@orm\preupdate`)
			}
		}
		if hook {
			out = append(out, method)
		}
	}
	return out
}

type phpHashWrite struct {
	key string
	at  analysis.Evidence
}

// passwordHashWrites finds mapped fields written from password_hash(), a
// PasswordHasherInterface::hash or a UserPasswordHasherInterface::hashPassword
// call: directly as $obj->p = …, or through a setter whose body assigns its
// first parameter to one property.
func (s *phpSet) passwordHashWrites(f *phpFlow, p *symfonyProject) []phpHashWrite {
	x := s.classIndex()
	var out []phpHashWrite
	files := slices.Clone(s.files)
	sort.Strings(files)
	for _, file := range files {
		m := s.modules[file]
		if m == nil || s.symfonyProjectOf(file) != p {
			continue
		}
		phpWalk(m.tree.RootNode(), func(n *sitter.Node) {
			if !s.passwordHashCall(m, n) {
				return
			}
			at := m.evidence(analysis.RoleCredential, n)
			parent := n.Parent()
			if parent != nil && parent.Kind() == "argument" {
				parent = parent.Parent()
			}
			if parent != nil && parent.Kind() == "arguments" {
				call := parent.Parent()
				if call == nil || call.Kind() != "member_call_expression" || len(phpArgs(call)) == 0 || phpArgs(call)[0].Id() != n.Id() {
					return
				}
				decl := s.receiverClass(m, n, phpField(call, "object"))
				if decl == nil {
					return
				}
				setter, module := x.methodOf(decl, phpText(m, phpField(call, "name")))
				if field := phpSetterField(module, setter); field != "" {
					out = append(out, phpHashWrite{key: f.doctrineFieldKeys(decl)[field], at: at})
				}
				return
			}
			if parent != nil && parent.Kind() == "assignment_expression" && phpField(parent, "right") != nil && phpField(parent, "right").Id() == n.Id() {
				left := phpField(parent, "left")
				if left == nil || left.Kind() != "member_access_expression" || phpField(left, "name") == nil || phpField(left, "name").Kind() != "name" {
					return
				}
				if decl := s.receiverClass(m, n, phpField(left, "object")); decl != nil {
					out = append(out, phpHashWrite{key: f.doctrineFieldKeys(decl)[phpText(m, phpField(left, "name"))], at: at})
				}
			}
		})
	}
	return out
}

func (s *phpSet) passwordHashCall(m *phpModule, n *sitter.Node) bool {
	switch n.Kind() {
	case "function_call_expression":
		name := strings.TrimPrefix(phpText(m, phpCallee(n)), `\`)
		_, local := m.funcs[name]
		return strings.EqualFold(name, "password_hash") && !local
	case "member_call_expression":
		method := phpText(m, phpField(n, "name"))
		want := ""
		switch method {
		case "hashPassword":
			want = symfonyUserPasswordHasher
		case "hash":
			want = symfonyPasswordHasher
		default:
			return false
		}
		return strings.EqualFold(s.receiverType(m, n, phpField(n, "object")), want)
	}
	return false
}

// receiverType returns the qualified declared type of a receiver: a typed
// parameter of the enclosing function, or $this->p for a promoted constructor
// parameter or typed property of the enclosing class.
func (s *phpSet) receiverType(m *phpModule, at, receiver *sitter.Node) string {
	x := s.classIndex()
	fn := phpEnclosing(at, "method_declaration", "function_definition")
	if receiver == nil || fn == nil {
		return ""
	}
	typed := func(params *sitter.Node, name string) string {
		for i := uint(0); params != nil && i < params.NamedChildCount(); i++ {
			param := params.NamedChild(i)
			if phpVarName(m, phpField(param, "name")) == name && phpField(param, "type") != nil {
				t := strings.TrimPrefix(phpText(m, phpField(param, "type")), "?")
				return x.qualify(m, t, param.StartByte())
			}
		}
		return ""
	}
	if receiver.Kind() == "variable_name" {
		return typed(phpField(fn, "parameters"), phpVarName(m, receiver))
	}
	if phpThisField(m, receiver) {
		class := phpEnclosing(fn, "class_declaration")
		name := phpText(m, phpField(receiver, "name"))
		body := phpField(class, "body")
		for i := uint(0); body != nil && i < body.NamedChildCount(); i++ {
			member := body.NamedChild(i)
			if member.Kind() == "method_declaration" && strings.EqualFold(phpText(m, phpField(member, "name")), "__construct") {
				if t := typed(phpField(member, "parameters"), name); t != "" {
					return t
				}
			}
			if member.Kind() == "property_declaration" && phpField(member, "type") != nil {
				for j := uint(0); j < member.NamedChildCount(); j++ {
					if e := member.NamedChild(j); e.Kind() == "property_element" && phpVarName(m, phpField(e, "name")) == name {
						return x.qualify(m, strings.TrimPrefix(phpText(m, phpField(member, "type")), "?"), member.StartByte())
					}
				}
			}
		}
	}
	return ""
}

// receiverClass resolves the class of a receiver variable: a typed parameter
// of the enclosing function or a `$v = new C(...)` assignment before at.
func (s *phpSet) receiverClass(m *phpModule, at, receiver *sitter.Node) *phpClassDecl {
	x := s.classIndex()
	if receiver == nil {
		return nil
	}
	if phpVarName(m, receiver) == "this" {
		if class := phpEnclosing(at, "class_declaration"); class != nil {
			d, _ := x.resolve(m, phpText(m, phpField(class, "name")), class.StartByte())
			return d
		}
		return nil
	}
	if receiver.Kind() != "variable_name" {
		return nil
	}
	name := phpVarName(m, receiver)
	if t := s.receiverType(m, at, receiver); t != "" {
		d, _ := x.resolve(m, `\`+t, at.StartByte())
		return d
	}
	fn := phpEnclosing(at, "method_declaration", "function_definition")
	var found *phpClassDecl
	phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
		if found != nil || n.StartByte() >= at.StartByte() || n.Kind() != "assignment_expression" || phpVarName(m, phpField(n, "left")) != name {
			return
		}
		right := phpField(n, "right")
		if right != nil && right.Kind() == "object_creation_expression" && right.NamedChildCount() > 0 {
			found, _ = x.resolve(m, phpText(m, right.NamedChild(0)), right.StartByte())
		}
	})
	return found
}

// phpSetterField returns the property a setter assigns from its first
// parameter, when its body assigns exactly one.
func phpSetterField(m *phpModule, fn *sitter.Node) string {
	if fn == nil {
		return ""
	}
	params := phpField(fn, "parameters")
	if params == nil || params.NamedChildCount() == 0 {
		return ""
	}
	param := phpVarName(m, phpField(params.NamedChild(0), "name"))
	field := ""
	count := 0
	phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
		if n.Kind() == "assignment_expression" && phpThisField(m, phpField(n, "left")) && phpVarName(m, phpField(n, "right")) == param {
			field = phpText(m, phpField(phpField(n, "left"), "name"))
			count++
		}
	})
	if count != 1 {
		return ""
	}
	return field
}

func phpEnclosing(n *sitter.Node, kinds ...string) *sitter.Node {
	for p := n; p != nil; p = p.Parent() {
		if slices.Contains(kinds, p.Kind()) {
			return p
		}
	}
	return nil
}

// analysisSecurityFields converts census entries for the wire, in key order.
func analysisSecurityFields(fields []securityField) []analysis.SecurityField {
	out := []analysis.SecurityField{}
	for _, f := range fields {
		out = append(out, analysis.SecurityField{StorageKey: f.storageKey, Roles: slices.Clone(f.roles), Evidence: slices.Clone(f.evidence)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StorageKey < out[j].StorageKey })
	return out
}

// phpPropertyElement returns the element of a property declaration that names
// field, so evidence cites the property, not its attributes.
func phpPropertyElement(m *phpModule, declaration *sitter.Node, field string) *sitter.Node {
	for i := uint(0); declaration != nil && i < declaration.NamedChildCount(); i++ {
		if e := declaration.NamedChild(i); e.Kind() == "property_element" && phpVarName(m, phpField(e, "name")) == field {
			return e
		}
	}
	return declaration
}
