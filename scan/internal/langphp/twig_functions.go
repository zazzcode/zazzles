package langphp

import (
	"maps"
	"slices"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Twig tags, filters and functions: https://twig.symfony.com/doc/3.x/
//
// Escape and raw strategies: https://twig.symfony.com/doc/3.x/filters/escape.html
// and https://twig.symfony.com/doc/3.x/filters/raw.html
// The nl2br filter pre-escapes its input: https://twig.symfony.com/doc/3.x/filters/nl2br.html
// Symfony bridge functions and app: https://symfony.com/doc/6.4/reference/twig_reference.html
// Extension parameters and safe markup: https://twig.symfony.com/doc/3.x/advanced.html
// Template compilation: https://twig.symfony.com/doc/3.x/functions/template_from_string.html
func (t *twigScope) apply(kind, name string, args []phpValue, at analysis.Evidence) twigResult {
	if extension, ok := t.flow.twigExtensions()[kind+":"+name]; ok {
		return t.extensionCall(extension, args, at)
	}
	var combined phpValue
	for _, v := range args {
		combined = phpCombine(combined, v)
	}
	if kind == "filter" {
		switch name {
		case "raw":
			return twigResult{value: combined, mode: "raw"}
		case "e", "escape":
			mode := "html"
			if len(args) > 1 {
				if strategy, ok := phpSQLText(args[1]); ok {
					mode = strategy
				} else {
					mode = "unknown"
				}
			}
			switch mode {
			case "html", "js", "css", "url", "html_attr":
			default:
				mode = "unknown"
			}
			return twigResult{value: combined, mode: mode}
		case "nl2br":
			return twigResult{value: combined, mode: "html"}
		case "upper", "lower", "capitalize", "title", "trim", "default", "first", "last", "join", "slice", "reverse", "replace", "format", "striptags", "u", "merge", "sort", "keys", "batch", "split", "abs", "round", "number_format", "url_encode", "json_encode":
			return twigResult{value: combined}
		case "date", "length", "format_datetime", "format_date", "format_number", "format_currency":
			return twigResult{value: twigLiteral("")}
		}
	} else {
		switch name {
		case "path", "url", "is_granted", "csrf_token", "random", "range", "constant", "max", "min", "date", "cycle":
			return twigResult{value: twigLiteral("")}
		case "asset", "absolute_url":
			if len(args) > 0 {
				combined.prefix = args[0].prefix
			}
			return twigResult{value: combined}
		case "include", "source":
			if name == "include" && len(args) > 0 {
				vars := t.vars
				if len(args) > 1 {
					vars = phpJoinProps(vars, args[1].fields)
				}
				t.include(args[0], vars, at)
			} else {
				t.templateGap(at, "Twig source or template name is unresolved")
			}
			return twigResult{}
		case "template_from_string":
			if len(args) > 0 {
				f := t.flow
				f.templateUse(t.call, "Twig\\Extension\\StringLoaderExtension::template_from_string", phpTransfer(args[0], at), t.call)
				return twigResult{value: args[0]}
			}
			return twigResult{}
		}
	}
	if len(combined.deps) > 0 {
		combined.gaps = append(combined.gaps, analysis.Gap{Kind: "twig_expression_unresolved", Detail: "Unmodeled Twig " + kind + ": " + name, At: at.Span})
	}
	return twigResult{value: combined, mode: "unknown"}
}

func (t *twigScope) property(base phpValue, name string, args []phpValue, method bool, at analysis.Evidence) phpValue {
	f := t.flow
	if base.binding == "twig_app" {
		switch name {
		case "request":
			return phpValue{binding: "symfony_request", class: symfonyRequestClass}
		case "user":
			const contract = `Symfony\Component\Security\Core\User\UserInterface`
			if decl := f.symfonyImplementation(contract); decl != nil {
				user, _ := f.symfonyEntity(decl, t.call)
				return user
			}
		case "flashes":
			return t.flashes(args, at)
		}
	}
	if method {
		if v, ok := f.requestCall(t.call, base, name, args); ok {
			for i := range v.deps {
				d := &v.deps[i]
				data := f.set.inputs[f.invocation.ID][d.dep.Source]
				source := at
				source.Kind = "input_source"
				source.Text = "Twig request " + data.container + " field " + d.key
				source.ModelText = at.Text
				d.dep.Source = source
				f.recordInput(source, data.container, d.key, data.origin)
			}
			return v
		}
	} else {
		if v, ok := symfonyRequestProperty(base, name); ok {
			return v
		}
	}
	if base.classDecl != nil && len(args) == 0 {
		if name != "" {
			index := f.set.classIndex()
			capitalized := strings.ToUpper(name[:1]) + name[1:]
			for _, getter := range []string{"get" + capitalized, "is" + capitalized, "has" + capitalized, name} {
				owner, fn, m, _ := index.method(base.classDecl, getter)
				if fn == nil || !symfonyPublicMethod(m, fn) {
					continue
				}
				self := base
				v := f.boundHelper(t.call, &phpBoundCallable{module: m, fn: fn, object: &self, class: owner}, nil)
				return phpTransfer(v, at)
			}
		}
		for _, field := range sortedTwigFields(base.props) {
			if strings.EqualFold(field, name) {
				return phpTransfer(base.props[field], at)
			}
		}
	}
	if base.binding == "db_row" && base.table != "" && len(args) == 0 {
		source := at
		source.Kind = "storage_source"
		return phpValue{deps: []phpDep{{dep: analysis.Dependency{Source: source, StorageKey: "php-sql:" + base.table + "." + name}, protection: "raw"}}}
	}
	if v, ok := base.fields[name]; ok && len(args) == 0 {
		return phpTransfer(v, at)
	}
	if method {
		base = phpProtect(base, "unknown")
		return phpTransfer(base, at)
	}
	return phpValue{unknown: true, gaps: base.gaps}
}

func (t *twigScope) flashes(args []phpValue, at analysis.Evidence) phpValue {
	var keys []string
	if len(args) > 0 {
		if key, ok := phpSQLText(args[0]); ok {
			keys = []string{key}
		}
		for _, name := range sortedTwigFields(args[0].fields) {
			if key, ok := phpSQLText(args[0].fields[name]); ok {
				keys = append(keys, key)
			}
		}
	}
	if len(keys) == 0 {
		keys = []string{"*"}
	}
	at.Kind = "storage_source"
	var out phpValue
	for _, key := range keys {
		out = phpCombine(out, phpValue{deps: []phpDep{{dep: analysis.Dependency{Source: at, StorageKey: "php-session:flash." + key}, protection: "raw"}}})
	}
	return out
}

func (f *phpFlow) twigFlashWrite(n *sitter.Node, kind, message phpValue) {
	key := "*"
	if literal, ok := phpSQLText(kind); ok {
		key = literal
	}
	storageKey := "php-session:flash." + key
	f.set.sessionWrites[storageKey] = append(f.set.sessionWrites[storageKey], phpWrite{value: phpTransfer(message, f.module.evidence("storage_write", n)), entry: f.entry.ID, evidence: f.module.evidence("storage_write", n)})
}

type twigExtension struct {
	decl                                *phpClassDecl
	method                              string
	safe, charset, environment, context bool
}

func (f *phpFlow) twigExtensions() map[string]twigExtension {
	index := f.set.classIndex()
	if found, ok := f.set.twig.extensions[f.symfony]; ok {
		return found
	}
	out := map[string]twigExtension{}
	f.set.twig.extensions[f.symfony] = out
	for _, name := range sortedTwigFields(index.byName) {
		for _, decl := range index.byName[name] {
			if f.set.symfonyProjectOf(decl.module.file) != f.symfony || !twigExtends(index, decl) {
				continue
			}
			for _, family := range []struct{ getter, class, key string }{
				{"getFunctions", `Twig\TwigFunction`, "function"},
				{"getFilters", `Twig\TwigFilter`, "filter"},
			} {
				_, fn, m, _ := index.method(decl, family.getter)
				if fn == nil {
					continue
				}
				phpWalk(phpField(fn, "body"), func(n *sitter.Node) {
					if n.Kind() != "return_statement" {
						return
					}
					phpWalk(n, func(call *sitter.Node) {
						if call.Kind() != "object_creation_expression" {
							return
						}
						class := firstNamedChild(call)
						if class == nil || !strings.EqualFold(index.qualify(m, phpText(m, class), class.StartByte()), family.class) {
							return
						}
						args := phpNewArguments(call)
						if len(args) < 2 {
							return
						}
						name, ok := phpStringLiteral(m, args[0])
						method := twigCallableMethod(m, args[1])
						if !ok || method == "" {
							return
						}
						e := twigExtension{decl: decl, method: method}
						if len(args) > 2 {
							e.readOptions(m, args[2])
						}
						out[family.key+":"+name] = e
					})
				})
			}
		}
	}
	return out
}

func twigExtends(index *phpClassIndex, decl *phpClassDecl) bool {
	for depth := 0; depth <= phpHelperDepthLimit && decl != nil; depth++ {
		base := firstNamedChild(firstChildOfKind(decl.node, "base_clause"))
		if base == nil {
			return false
		}
		if strings.EqualFold(index.qualify(decl.module, phpText(decl.module, base), base.StartByte()), `Twig\Extension\AbstractExtension`) {
			return true
		}
		decl, _ = index.parentOf(decl)
	}
	return false
}

func twigCallableMethod(m *phpModule, n *sitter.Node) string {
	switch n.Kind() {
	case "array_creation_expression":
		if n.NamedChildCount() != 2 {
			return ""
		}
		receiver := phpText(m, firstNamedChild(n.NamedChild(0)))
		if receiver != "$this" && receiver != "self::class" {
			return ""
		}
		name, _ := phpStringLiteral(m, firstNamedChild(n.NamedChild(1)))
		return name
	case "member_call_expression", "scoped_call_expression":
		if strings.TrimSpace(phpText(m, phpField(n, "arguments"))) != "(...)" {
			return ""
		}
		receiver := phpText(m, phpField(n, "object"))
		scope := phpText(m, phpField(n, "scope"))
		if receiver != "$this" && scope != "self" {
			return ""
		}
		return phpText(m, phpField(n, "name"))
	}
	return ""
}

func (e *twigExtension) readOptions(m *phpModule, node *sitter.Node) {
	if node.Kind() != "array_creation_expression" {
		return
	}
	for i := uint(0); i < node.NamedChildCount(); i++ {
		pair := node.NamedChild(i)
		if pair.Kind() != "array_element_initializer" || pair.NamedChildCount() != 2 {
			continue
		}
		name, _ := phpStringLiteral(m, pair.NamedChild(0))
		v := pair.NamedChild(1)
		switch name {
		case "is_safe":
			phpWalk(v, func(n *sitter.Node) {
				if s, ok := phpStringLiteral(m, n); ok && s == "html" {
					e.safe = true
				}
			})
		case "needs_environment":
			e.environment = phpText(m, v) == "true"
		case "needs_context":
			e.context = phpText(m, v) == "true"
		case "needs_charset":
			e.charset = phpText(m, v) == "true"
		}
	}
}

func (t *twigScope) extensionCall(e twigExtension, args []phpValue, at analysis.Evidence) twigResult {
	f := t.flow
	owner, fn, m, _ := f.set.classIndex().method(e.decl, e.method)
	if fn == nil {
		var v phpValue
		for _, a := range args {
			v = phpCombine(v, a)
		}
		v.gaps = append(v.gaps, analysis.Gap{Kind: "twig_expression_unresolved", Detail: "Twig extension callable cannot be resolved", At: at.Span})
		return twigResult{value: v, mode: "unknown"}
	}
	var values []phpValue
	if e.charset {
		values = append(values, phpValue{unknown: true})
	}
	if e.environment {
		values = append(values, phpValue{binding: "symfony_opaque", class: `Twig\Environment`})
	}
	if e.context {
		values = append(values, phpValue{unknown: true})
	}
	for _, arg := range args {
		values = append(values, phpTransfer(arg, at))
	}
	self := f.symfonyServiceObject(e.decl, t.call)
	prior := len(f.context)
	f.context = append(f.context, at)
	out := f.boundHelper(t.call, &phpBoundCallable{module: m, fn: fn, object: &self, class: owner}, values)
	f.context = f.context[:prior]
	if e.safe {
		return twigResult{value: out, mode: "raw"}
	}
	return twigResult{value: out}
}

func sortedTwigFields[V any](m map[string]V) []string {
	return slices.Sorted(maps.Keys(m))
}
