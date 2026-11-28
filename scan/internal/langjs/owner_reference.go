package langjs

import (
	"sort"
	"strings"
	"unicode"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/parse"
)

// Owner references (detection generalization 22). A field of a model that is
// the foreign key of a declared association to an account model (a model that
// holds a credential attribute) carries the census role owner_reference. The
// role comes from the association contract, never from a field name:
//
//   - Sequelize Target.belongsTo(Account, opts): the key is opts.foreignKey
//     when it is a string literal or { name: '<literal>' }; with no foreignKey
//     it is the documented default, the camel-cased `as` (or the target
//     model's name) plus "Id", as in Ship.belongsTo(Captain) giving captainId
//     (https://sequelize.org/docs/v6/core-concepts/assocs/, "Foreign Keys");
//   - Mongoose: a schema path with ref: '<Account model>' is the key itself
//     (https://mongoosejs.com/docs/populate.html).
//
// One association step only. An association whose options are not literal
// records owner_reference_unresolved and sets no role. The search follows the
// owned-model search of authorization_reads.go and does not change it.

// ownerRef is one association from a census target to an account model.
type ownerRef struct {
	field      string
	evidence   analysis.Evidence
	unresolved bool
}

// ownerKeys maps a model identity to its associations to account models, in
// source order. It is built once.
func (s *moduleSet) ownerKeys() map[string][]ownerRef {
	if s.owner != nil {
		return s.owner
	}
	s.owner = map[string][]ownerRef{}
	files := make([]string, 0, len(s.modules))
	for file := range s.modules {
		files = append(files, file)
	}
	sort.Strings(files)
	add := func(id string, ref ownerRef) {
		for _, have := range s.owner[id] {
			if have.unresolved == ref.unresolved && have.field == ref.field {
				return
			}
		}
		s.owner[id] = append(s.owner[id], ref)
	}
	type labeled struct {
		module *sourceModule
		name   string
	}
	labels := map[string]labeled{}
	for _, file := range files {
		m := s.modules[file]
		for _, name := range topVariableNames(m) {
			if id := s.modelIdentity(m, name, 0); strings.HasPrefix(id, "mongoose:") {
				if _, seen := labels[id]; !seen {
					labels[id] = labeled{m, name}
				}
			}
		}
	}
	for _, file := range files {
		m := s.modules[file]
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" || memberName(m, fn) != "belongsTo" {
				return
			}
			owner, account := fn.ChildByFieldName("object"), unwrapTS(firstArg(args))
			if owner == nil || account == nil || owner.Kind() != "identifier" || account.Kind() != "identifier" {
				return
			}
			if shadowed(call, owner.Utf8Text(m.src), m.src) || shadowed(call, account.Utf8Text(m.src), m.src) {
				return
			}
			id := s.modelIdentity(m, owner.Utf8Text(m.src), 0)
			accountID := s.modelIdentity(m, account.Utf8Text(m.src), 0)
			if !strings.HasPrefix(id, "sequelize:") || !strings.HasPrefix(accountID, "sequelize:") || !s.holdsCredential(m, account.Utf8Text(m.src)) {
				return
			}
			ev := m.evidence("owner_association", call)
			var opts *sitter.Node
			if len(namedArgs(args)) > 1 {
				opts = unwrapTS(namedArgs(args)[1])
			}
			name, ok := sequelizeForeignKey(m, opts, accountClass(accountID))
			add(id, ownerRef{field: name, evidence: ev, unresolved: !ok})
		})
	}
	ids := make([]string, 0, len(labels))
	for id := range labels {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		l := labels[id]
		info, ok := s.modelAttributes(l.module, l.name)
		if !ok {
			continue
		}
		for _, a := range info.attrs {
			spec := unwrapTS(a.node.ChildByFieldName("value"))
			if spec == nil || spec.Kind() != "object" {
				continue
			}
			ref, ok := stringLiteral(property(spec, "ref", info.module.src), info.module.src)
			if !ok {
				continue
			}
			if target, known := labels["mongoose:"+ref]; known && s.holdsCredential(target.module, target.name) {
				add(id, ownerRef{field: a.name, evidence: info.module.evidence("owner_association", a.node)})
			}
		}
	}
	return s.owner
}

func namedArgs(args *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for i := uint(0); i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() != "comment" {
			out = append(out, c)
		}
	}
	return out
}

// accountClass is the class name of a sequelize model identity.
func accountClass(id string) string {
	return id[strings.LastIndex(id, ":")+1:]
}

// sequelizeForeignKey returns the attribute name a belongsTo association adds
// to its source model, and false when the options do not state it literally.
func sequelizeForeignKey(m *sourceModule, opts *sitter.Node, accountName string) (string, bool) {
	base := accountName
	if opts != nil {
		if opts.Kind() != "object" {
			return "", false
		}
		for i := uint(0); i < opts.NamedChildCount(); i++ {
			if opts.NamedChild(i).Kind() == "spread_element" {
				return "", false
			}
		}
		if fk := property(opts, "foreignKey", m.src); fk != nil {
			fk = unwrapTS(fk)
			if fk.Kind() == "object" {
				name, ok := stringLiteral(unwrapTS(property(fk, "name", m.src)), m.src)
				return name, ok && name != ""
			}
			name, ok := stringLiteral(fk, m.src)
			return name, ok && name != ""
		}
		if as := property(opts, "as", m.src); as != nil {
			name, ok := stringLiteral(unwrapTS(as), m.src)
			if !ok || name == "" {
				return "", false
			}
			base = name
		}
	}
	if base == "" {
		return "", false
	}
	r := []rune(base)
	r[0] = unicode.ToLower(r[0])
	return string(r) + "Id", true
}

// ownerReferenceGaps lists owner_reference_unresolved for each association of
// the target whose foreign key is not literal. The slice is never nil.
func (s *moduleSet) ownerReferenceGaps(info modelInfo) []analysis.Gap {
	gaps := []analysis.Gap{}
	for _, ref := range s.ownerKeys()[info.id] {
		if ref.unresolved {
			gaps = append(gaps, analysis.Gap{Kind: analysis.OwnerReferenceUnresolved, Detail: "An association to an account model has options that are not literal; its foreign key is not known.", At: ref.evidence.Span})
		}
	}
	return gaps
}

// overwriteNote is the note of a write whose attributes a stage overwrites.
const overwriteNote = " A middleware registered for this endpoint overwrites some request fields before the write; those attributes are not request-chosen and are left out."

// handwrittenOverwrites applies the rule generated endpoints use
// (overwrittenFields) to a handwritten whole-body write: the attributes that
// the entry's registered stages assign, or that the handler assigns as
// req.body.<name> in a top-level statement before the write, are left out of
// the written attributes with their chain_overwrite evidence. A conditional
// assignment, an alias of the body and a computed key are not followed.
func (s *moduleSet) handwrittenOverwrites(e analysis.EntryPoint, m *sourceModule, fn *sitter.Node, p handlerParams, write *sitter.Node, info modelInfo) (modelInfo, []analysis.Evidence, string) {
	over := map[string]analysis.Evidence{}
	if rm := s.modules[e.Location.Span.File]; rm != nil {
		if reg := parse.NodeAt(rm.tree.RootNode(), e.Location.Span.StartByte, e.Location.Span.EndByte); reg != nil && reg.Kind() == "call_expression" {
			var chain []*sitter.Node
			if args := reg.ChildByFieldName("arguments"); args != nil {
				for i := uint(1); i+1 < args.NamedChildCount(); i++ {
					chain = append(chain, args.NamedChild(i))
				}
			}
			predecessors, _ := s.httpPredecessors(rm, e, reg)
			for _, call := range predecessors {
				if args := call.ChildByFieldName("arguments"); args != nil {
					for i := uint(0); i < args.NamedChildCount(); i++ {
						chain = append(chain, args.NamedChild(i))
					}
				}
			}
			for name, ev := range s.overwrittenFields(rm, chain) {
				over[name] = ev
			}
		}
	}
	for name, ev := range handlerAssignments(m, fn, p, write) {
		over[name] = ev
	}
	if len(over) == 0 {
		return info, nil, ""
	}
	writable, extra, changed := info, []analysis.Evidence(nil), false
	writable.attrs = nil
	for _, a := range info.attrs {
		if ev, ok := over[a.name]; ok {
			extra, changed = append(extra, ev), true
			continue
		}
		writable.attrs = append(writable.attrs, a)
	}
	if !changed {
		return info, nil, ""
	}
	return writable, extra, strings.TrimSpace(overwriteNote)
}

// handlerAssignments returns the request-body assignments `req.body.<name> = …`
// among the top-level statements of the handler body that precede the
// statement holding the write.
func handlerAssignments(m *sourceModule, fn *sitter.Node, p handlerParams, write *sitter.Node) map[string]analysis.Evidence {
	out := map[string]analysis.Evidence{}
	body := fn.ChildByFieldName("body")
	if body == nil || body.Kind() != "statement_block" || p.request == "" {
		return out
	}
	for i := uint(0); i < body.NamedChildCount(); i++ {
		stmt := body.NamedChild(i)
		if stmt.StartByte() <= write.StartByte() && write.EndByte() <= stmt.EndByte() {
			break
		}
		if stmt.Kind() != "expression_statement" || stmt.NamedChildCount() != 1 {
			continue
		}
		as := stmt.NamedChild(0)
		if as.Kind() != "assignment_expression" {
			continue
		}
		left := as.ChildByFieldName("left")
		if left == nil || left.Kind() != "member_expression" {
			continue
		}
		bag := left.ChildByFieldName("object")
		if bag == nil || bag.Kind() != "member_expression" || memberName(m, bag) != "body" {
			continue
		}
		if root := bag.ChildByFieldName("object"); root == nil || root.Kind() != "identifier" || root.Utf8Text(m.src) != p.request {
			continue
		}
		out[memberName(m, left)] = m.evidence("chain_overwrite", as)
	}
	return out
}
