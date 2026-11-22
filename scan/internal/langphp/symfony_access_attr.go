package langphp

import (
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

const (
	symfonyIsGranted = `Symfony\Component\Security\Http\Attribute\IsGranted`
	sensioIsGranted  = `Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted`
)

// applyAccessAttributes merges #[IsGranted], the docblock form and a leading
// denyAccessUnlessGranted into the rule result (D-3).
func (f *phpFlow) applyAccessAttributes(base analysis.EntryAccess, class *phpClassDecl, action *sitter.Node) analysis.EntryAccess {
	if class == nil {
		return base
	}
	base = mergeAccess(base, f.grantedAttribute(class.module, class.node))
	base = mergeAccess(base, f.grantedDocblock(class.module, class.node))
	if action != nil {
		base = mergeAccess(base, f.grantedAttribute(class.module, action))
		base = mergeAccess(base, f.grantedDocblock(class.module, action))
		base = mergeAccess(base, f.leadingDeny(class.module, action))
	}
	return base
}

func (f *phpFlow) grantedAttribute(m *phpModule, node *sitter.Node) analysis.EntryAccess {
	var out analysis.EntryAccess
	phpWalk(phpField(node, "attributes"), func(attr *sitter.Node) {
		if attr.Kind() != "attribute" {
			return
		}
		name := f.set.classIndex().qualify(m, phpText(m, attr.NamedChild(0)), attr.StartByte())
		if !strings.EqualFold(name, symfonyIsGranted) && !strings.EqualFold(name, sensioIsGranted) {
			return
		}
		out = mergeAccess(out, f.isGrantedAccess(m, attr))
	})
	if out.Authentication == "" {
		return analysis.EntryAccess{}
	}
	return out
}

func (f *phpFlow) isGrantedAccess(m *phpModule, attr *sitter.Node) analysis.EntryAccess {
	at := m.evidence("is_granted", attr)
	if attributeHasSubject(m, attr) {
		return unresolvedAccess("voter_unmodeled", "IsGranted subject is a voter this reader does not model", at)
	}
	role, ok := attributeFirstString(m, attr)
	if !ok {
		return unresolvedAccess("voter_unmodeled", "IsGranted attribute is not a literal role", at)
	}
	if strings.HasPrefix(role, "ROLE_") || strings.HasPrefix(role, "IS_AUTHENTICATED") {
		return analysis.EntryAccess{Authentication: analysis.AccessRequired, Roles: []string{role}, Sources: []analysis.Evidence{at}}
	}
	return unresolvedAccess("voter_unmodeled", "IsGranted attribute is not a role", at)
}

func (f *phpFlow) grantedDocblock(m *phpModule, node *sitter.Node) analysis.EntryAccess {
	comment := previousComment(node)
	if comment == nil {
		return analysis.EntryAccess{}
	}
	text := phpText(m, comment)
	at := m.evidence("is_granted", comment)
	if strings.Contains(text, "@Security") {
		return unresolvedAccess("access_expression_unmodeled", "Security expression is not modeled", at)
	}
	role, ok := docblockRole(text, "@IsGranted")
	if !ok {
		return analysis.EntryAccess{}
	}
	if strings.HasPrefix(role, "ROLE_") || strings.HasPrefix(role, "IS_AUTHENTICATED") {
		return analysis.EntryAccess{Authentication: analysis.AccessRequired, Roles: []string{role}, Sources: []analysis.Evidence{at}}
	}
	return unresolvedAccess("voter_unmodeled", "IsGranted docblock is not a role", at)
}

func (f *phpFlow) leadingDeny(m *phpModule, action *sitter.Node) analysis.EntryAccess {
	body := phpField(action, "body")
	if body == nil || body.NamedChildCount() == 0 {
		return analysis.EntryAccess{}
	}
	stmt := body.NamedChild(0)
	call := denyCall(stmt)
	if call == nil {
		return analysis.EntryAccess{}
	}
	if phpText(m, phpField(call, "name")) != "denyAccessUnlessGranted" {
		return analysis.EntryAccess{}
	}
	args := phpArgs(call)
	if len(args) == 0 {
		return analysis.EntryAccess{}
	}
	role, ok := phpStringLiteral(m, args[0])
	at := m.evidence("is_granted", call)
	if !ok {
		return unresolvedAccess("voter_unmodeled", "denyAccessUnlessGranted argument is not a literal role", at)
	}
	if strings.HasPrefix(role, "ROLE_") || strings.HasPrefix(role, "IS_AUTHENTICATED") {
		return analysis.EntryAccess{Authentication: analysis.AccessRequired, Roles: []string{role}, Sources: []analysis.Evidence{at}}
	}
	return unresolvedAccess("voter_unmodeled", "denyAccessUnlessGranted argument is not a role", at)
}

func denyCall(stmt *sitter.Node) *sitter.Node {
	if stmt == nil || stmt.Kind() != "expression_statement" || stmt.NamedChildCount() != 1 {
		return nil
	}
	call := stmt.NamedChild(0)
	if call.Kind() != "member_call_expression" {
		return nil
	}
	return call
}

func attributeHasSubject(m *phpModule, attr *sitter.Node) bool {
	args := phpField(attr, "parameters")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		arg := args.NamedChild(i)
		if phpText(m, phpField(arg, "name")) == "subject" {
			return true
		}
		if i > 0 && phpText(m, phpField(arg, "name")) == "" {
			return true
		}
	}
	return false
}

func attributeFirstString(m *phpModule, attr *sitter.Node) (string, bool) {
	args := phpField(attr, "parameters")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	arg := args.NamedChild(0)
	value := arg
	if arg.NamedChildCount() > 0 {
		value = arg.NamedChild(arg.NamedChildCount() - 1)
	}
	return phpStringLiteral(m, value)
}

func previousComment(node *sitter.Node) *sitter.Node {
	for prev := node.PrevNamedSibling(); prev != nil; prev = prev.PrevNamedSibling() {
		if prev.Kind() == "comment" {
			return prev
		}
		if prev.Kind() != "attribute_list" && prev.Kind() != "attribute" {
			break
		}
	}
	return nil
}

func docblockRole(text, marker string) (string, bool) {
	i := strings.Index(text, marker)
	if i < 0 {
		return "", false
	}
	rest := text[i+len(marker):]
	rest = strings.TrimLeft(rest, " \t(")
	if rest == "" {
		return "", false
	}
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return "", false
	}
	rest = rest[1:]
	end := strings.IndexByte(rest, quote)
	if end < 0 {
		return "", false
	}
	return rest[:end], true
}

func unresolvedAccess(kind, detail string, at analysis.Evidence) analysis.EntryAccess {
	return analysis.EntryAccess{
		Authentication: analysis.AccessUnresolved,
		Sources:        []analysis.Evidence{at},
		Gaps:           []analysis.Gap{{Kind: kind, Detail: detail, At: at.Span}},
	}
}

func mergeAccess(base, extra analysis.EntryAccess) analysis.EntryAccess {
	if extra.Authentication == "" {
		return base
	}
	if base.Authentication == "" {
		return extra
	}
	out := base
	out.Sources = append(append([]analysis.Evidence{}, base.Sources...), extra.Sources...)
	out.Gaps = append(append([]analysis.Gap{}, base.Gaps...), extra.Gaps...)
	out.Roles = mergeRoles(base.Roles, extra.Roles)
	switch {
	case base.Authentication == analysis.AccessUnresolved || extra.Authentication == analysis.AccessUnresolved:
		out.Authentication = analysis.AccessUnresolved
	case base.Authentication == analysis.AccessRequired || extra.Authentication == analysis.AccessRequired:
		out.Authentication = analysis.AccessRequired
	default:
		out.Authentication = analysis.AccessNone
	}
	return out
}

func mergeRoles(a, b []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, role := range append(append([]string{}, a...), b...) {
		if role == "" || seen[role] {
			continue
		}
		seen[role] = true
		out = append(out, role)
	}
	return out
}
