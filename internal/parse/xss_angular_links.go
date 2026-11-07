package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

// angularUnit is an analyzed component, kept to link dialogs across components.
type angularUnit struct {
	module  *sourceModule
	class   *sitter.Node
	context *clientContext
}

// noteTrustedField remembers a trusted value by the object field that holds it.
func (f *flow) noteTrustedField(field string, v value) {
	if f.client == nil || v.trustedContext == "" || len(v.deps) == 0 {
		return
	}
	if f.client.trustedFields == nil {
		f.client.trustedFields = map[string]value{}
	}
	f.client.trustedFields[field] = combine(f.client.trustedFields[field], v)
}

// iterationField resolves `item.field` when item is declared by the template itself
// (`let item`) and the component stored a trusted value in that field.
func (c *clientContext) iterationField(template, expression string) (value, bool) {
	parts := strings.Split(expression, ".")
	if len(parts) != 2 {
		return value{}, false
	}
	declared := regexp.MustCompile(`\blet\s+` + regexp.QuoteMeta(parts[0]) + `\b`)
	if !declared.MatchString(template) {
		return value{}, false
	}
	v, ok := c.trustedFields[parts[1]]
	return v, ok
}

// clientForOf binds a for...of variable to an element of the iterated value.
func (f *flow) clientForOf(n *sitter.Node) bool {
	left, right, body := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("body")
	if f.client == nil || left == nil || right == nil || body == nil || left.Kind() != "identifier" {
		return false
	}
	if operator := n.ChildByFieldName("operator"); operator == nil || operator.Utf8Text(f.module.src) != "of" {
		return false
	}
	v := f.eval(right)
	if v.apiPath == "" {
		return false
	}
	if v.responseField != "*" {
		v.responseField = joinField(v.responseField, "[]")
	}
	v.deps = fieldDeps(v.deps, "[]")
	f.env[left.Utf8Text(f.module.src)] = f.transfer(v, "collection_element", left)
	f.statement(body)
	return true
}

func angularSelector(m *sourceModule, class *sitter.Node) string {
	selector := ""
	walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() != 1 || call.Parent() == nil || call.Parent().Kind() != "decorator" || call.EndByte() > class.EndByte() {
			return
		}
		if m.imports[fn.Utf8Text(m.src)].name == "Component" {
			selector, _ = stringLiteral(property(args.NamedChild(0), "selector", m.src), m.src)
		}
	})
	return selector
}

// dialogOpener returns the MatDialog.open(Component, ...) call for a class name.
func dialogOpener(u *angularUnit, name string) *sitter.Node {
	var found *sitter.Node
	walkCalls(u.class, func(call *sitter.Node) {
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Kind() != "member_expression" || args.NamedChildCount() == 0 {
			return
		}
		prop := fn.ChildByFieldName("property")
		field := strings.TrimPrefix(fn.ChildByFieldName("object").Utf8Text(u.module.src), "this.")
		injection := u.context.injected[field]
		if prop != nil && prop.Utf8Text(u.module.src) == "open" && injection.module == "@angular/material/dialog" && args.NamedChild(0).Utf8Text(u.module.src) == name {
			found = call
		}
	})
	return found
}

// linkAngularDialogs follows a trusted field into a dialog. All three edges must be
// source-backed: the dialog template renders MAT_DIALOG_DATA at that field, a component
// opens this dialog, and that component's selector is used in the template of the
// component that stored the trusted value.
func (s *moduleSet) linkAngularDialogs(report *analysis.AnalysisReport) {
	consumed := map[string]bool{}
	for _, dialog := range s.angularUnits {
		if dialog.context.template == nil {
			continue
		}
		name := dialog.class.ChildByFieldName("name").Utf8Text(dialog.module.src)
		root := ""
		for field, injection := range dialog.context.injected {
			if injection.module == "@angular/material/dialog" && injection.name == "MAT_DIALOG_DATA" {
				root = field
			}
		}
		if root == "" {
			continue
		}
		file := *dialog.context.template
		for _, match := range angularBinding.FindAllStringSubmatchIndex(file.Text, -1) {
			parts := strings.Split(strings.ReplaceAll(strings.TrimSpace(file.Text[match[6]:match[7]]), "?.", "."), ".")
			if !strings.EqualFold(file.Text[match[2]:match[3]], "innerHTML") || len(parts) < 2 || parts[0] != root {
				continue
			}
			field := parts[len(parts)-1]
			for _, opener := range s.angularUnits {
				call := dialogOpener(opener, name)
				selector := angularSelector(opener.module, opener.class)
				if call == nil || selector == "" {
					continue
				}
				for _, owner := range s.angularUnits {
					v, ok := owner.context.trustedFields[field]
					if !ok || owner.context.template == nil || !strings.Contains(owner.context.template.Text, "<"+selector) {
						continue
					}
					flow := newClientFlow(s, owner.module, owner.context)
					bindings := append(append([]analysis.Evidence{}, dialog.context.bindings...), opener.module.evidence("dialog_open", call))
					flow.angularRecord(textRange(file, match[0], match[1], "angular_output"), v, "html_text", bindings, consumed)
					addClientUses(report, owner.context, flow.uses)
				}
			}
		}
	}
	if len(consumed) == 0 {
		return
	}
	var uses []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Sink.Kind != "trust_bypass" || !consumed[u.Sink.Span.File+":"+u.Sink.Text] {
			uses = append(uses, u)
		}
	}
	report.Uses = uses
}
