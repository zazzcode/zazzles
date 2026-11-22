package langphp

import (
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"gopkg.in/yaml.v3"
)

type twigInventory struct {
	files      map[string]bool
	text       *parse.TextSources
	extensions map[*symfonyProject]map[string]twigExtension
}

func newTwigInventory(files []string, root string) twigInventory {
	allowed := make(map[string]bool, len(files))
	for _, file := range files {
		allowed[file] = true
	}
	return twigInventory{files: allowed, text: parse.NewTextSources(root), extensions: map[*symfonyProject]map[string]twigExtension{}}
}

type twigScope struct {
	flow     *phpFlow
	call     *sitter.Node
	vars     map[string]phpValue
	visiting map[string]bool
	recorded map[analysis.Span]int
}

func (f *phpFlow) renderTwig(call *sitter.Node, name phpValue, context phpValue) {
	t := twigScope{flow: f, call: call, vars: maps.Clone(context.fields), visiting: map[string]bool{}, recorded: map[analysis.Span]int{}}
	// Repeated rendering of one template in this entry adds paths to the
	// existing interpolation rather than duplicating its sink identity.
	for i, use := range f.report.Uses {
		if use.EntryID == f.entry.ID && use.APIModel != nil && use.APIModel.ID == "twig-html-output-v1" {
			t.recorded[use.Sink.Span] = i
		}
	}
	if t.vars == nil {
		t.vars = map[string]phpValue{}
	}
	t.vars["app"] = phpValue{binding: "twig_app"}
	cfg := f.symfony.configs[path.Join(f.symfony.root, "config/packages/twig.yaml")]
	globals := symfonyYAMLValue(symfonyYAMLValue(cfg.value, "twig"), "globals")
	if globals != nil && globals.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(globals.Content); i += 2 {
			name, node := globals.Content[i].Value, globals.Content[i+1]
			if node.Kind != yaml.ScalarNode {
				continue
			}
			value := node.Value
			if class, service := strings.CutPrefix(value, "@"); service {
				t.vars[name] = f.autowireSymfony(class, call)
			} else {
				t.vars[name] = twigLiteral(value)
			}
		}
	}
	prior := len(f.context)
	f.context = append(f.context, f.module.evidence("render_binding", call))
	t.scan(name, f.module.evidence("template_render", call))
	f.context = f.context[:prior]
}

func (t *twigScope) templateGap(at analysis.Evidence, detail string) {
	t.flow.gaps = append(t.flow.gaps, analysis.Gap{Kind: "twig_template_unresolved", Detail: detail, At: at.Span})
}

func (t *twigScope) scan(name phpValue, at analysis.Evidence) {
	f := t.flow
	file, ok := phpSQLText(name)
	if !ok || file == "" || strings.Contains(file, "\\") {
		t.templateGap(at, "Template name is not a literal path")
		return
	}
	cfg := f.symfony.configs[path.Join(f.symfony.root, "config/packages/twig.yaml")]
	dir := symfonyYAMLString(symfonyYAMLValue(symfonyYAMLValue(cfg.value, "twig"), "default_path"))
	if dir == "" {
		dir = "templates"
	}
	dir = strings.TrimPrefix(dir, "%kernel.project_dir%/")
	if !safePHPPath(dir) || !safePHPPath(strings.TrimPrefix(file, "/")) {
		t.templateGap(at, "Template path is outside the project inventory")
		return
	}
	file = path.Join(f.symfony.root, dir, strings.TrimPrefix(file, "/"))
	if !f.set.twig.files[file] {
		t.templateGap(at, "Template is absent from the walk inventory")
		return
	}
	if t.visiting[file] || len(t.visiting) >= phpHelperDepthLimit+1 {
		t.templateGap(at, "Template expansion reaches a cycle or depth bound")
		return
	}
	source, ok := f.set.twig.text.Read(file)
	if !ok {
		t.templateGap(at, "Template cannot be read inside the project")
		return
	}
	t.visiting[file] = true
	defer delete(t.visiting, file)
	t.scanRegions(source)
}

type twigRegion struct {
	kind, expression string
	start, end       int
}

func twigRegions(src string) []twigRegion {
	var regions []twigRegion
	start := 0
	for i := 0; i+1 < len(src); i++ {
		if src[i] != '{' {
			continue
		}
		kind, end := src[i+1], byte(0)
		switch kind {
		case '{':
			end = '}'
		case '%':
			end = '%'
		case '#':
			end = '#'
		default:
			continue
		}
		last := twigRegionEnd(src, i+2, end, kind)
		if last < 0 {
			break
		}
		if i > start {
			regions = append(regions, twigRegion{kind: "text", expression: src[start:i], start: start, end: i})
		}
		expr := strings.TrimSpace(src[i+2 : last])
		if strings.HasPrefix(src[i+2:last], "-") {
			expr = strings.TrimSpace(strings.TrimPrefix(expr, "-"))
		}
		if strings.HasSuffix(src[i+2:last], "-") {
			expr = strings.TrimSpace(strings.TrimSuffix(expr, "-"))
		}
		regions = append(regions, twigRegion{kind: string(kind), expression: expr, start: i, end: last + 2})
		i = last + 1
		start = i + 1
	}
	if start < len(src) {
		regions = append(regions, twigRegion{kind: "text", expression: src[start:], start: start, end: len(src)})
	}
	return regions
}

func twigRegionEnd(src string, start int, end, kind byte) int {
	var quote byte
	depth := 0
	for i := start; i+1 < len(src); i++ {
		c := src[i]
		if kind == '#' {
			if c == end && src[i+1] == '}' {
				return i
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		if depth == 0 && c == end && src[i+1] == '}' {
			return i
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(', '[', '{':
			depth++
		case ')', ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return -1
}

func (t *twigScope) scanRegions(source analysis.Evidence) {
	var html strings.Builder
	autoescape := []string{t.flow.twigAutoescape()}
	type block struct {
		tag           string
		start, branch map[string]phpValue
	}
	var blocks []block
	for _, r := range twigRegions(source.Text) {
		switch r.kind {
		case "text":
			html.WriteString(r.expression)
			continue
		case "#":
			continue
		}
		at := parse.TextRange(source, r.start, r.end, "template_output")
		if r.kind == "{" {
			t.output(r.expression, at, html.String(), autoescape[len(autoescape)-1], parse.RenderMarkup(source, r.start, r.end))
			html.WriteByte('x')
			continue
		}
		tag, rest, _ := strings.Cut(r.expression, " ")
		rest = strings.TrimSpace(rest)
		at.Kind = "template_tag"
		switch tag {
		case "autoescape":
			autoescape = append(autoescape, twigAutoescapeTag(rest))
		case "macro":
			// A macro body renders with its own arguments and returns safe
			// markup. Its outputs are outside the modeled render subset.
			t.templateGap(at, "Twig macro "+rest+" is not analyzed")
		case "import", "from":
			if _, alias, ok := strings.Cut(rest, " as "); ok && tag == "import" && twigIdentifier(strings.TrimSpace(alias)) {
				t.vars[strings.TrimSpace(alias)] = phpValue{binding: "twig_macros"}
			}
		case "endautoescape":
			if len(autoescape) > 1 {
				autoescape = autoescape[:len(autoescape)-1]
			}
		case "include", "extends":
			t.includeTag(rest, at)
		case "set":
			name, value, ok := strings.Cut(rest, "=")
			if name = strings.TrimSpace(name); ok && twigIdentifier(name) {
				v, _ := t.eval(value, at)
				t.vars[name] = v
			}
		case "for":
			names, expr, ok := strings.Cut(rest, " in ")
			if !ok {
				continue
			}
			v, _ := t.eval(expr, at)
			bindings := strings.Split(names, ",")
			blocks = append(blocks, block{tag: "for", start: maps.Clone(t.vars)})
			name := strings.TrimSpace(bindings[len(bindings)-1])
			if twigIdentifier(name) {
				t.vars[name] = v
			}
		case "if":
			blocks = append(blocks, block{tag: "if", start: maps.Clone(t.vars)})
		case "else", "elseif":
			if len(blocks) > 0 {
				b := &blocks[len(blocks)-1]
				b.branch = phpJoinProps(b.branch, t.vars)
				t.vars = maps.Clone(b.start)
			}
		case "endfor", "endif":
			if len(blocks) > 0 && "end"+blocks[len(blocks)-1].tag == tag {
				b := blocks[len(blocks)-1]
				blocks = blocks[:len(blocks)-1]
				b.branch = phpJoinProps(b.branch, b.start)
				t.vars = phpJoinProps(b.branch, t.vars)
				t.vars = maps.Clone(t.vars)
			}
		}
	}
}

func (t *twigScope) includeTag(expr string, at analysis.Evidence) {
	p := newTwigParser(expr)
	x := p.expression(0)
	locals := maps.Clone(t.vars)
	name := phpValue{}
	if x != nil && x.kind == "literal" {
		name = twigLiteral(x.text)
	}
	if p.take("with") {
		if extra := p.expression(0); extra != nil {
			maps.Copy(locals, t.value(extra, at).value.fields)
		}
	}
	t.include(name, locals, at)
}

func (t *twigScope) include(name phpValue, vars map[string]phpValue, at analysis.Evidence) {
	child := *t
	child.vars = vars
	child.scan(name, at)
}

// twigAutoescape is the project's default strategy from twig.yaml: "name"
// (by template file name, the default), "html", "off" or "unknown".
// https://symfony.com/doc/6.4/reference/configuration/twig.html#autoescape
func (f *phpFlow) twigAutoescape() string {
	cfg := f.symfony.configs[path.Join(f.symfony.root, "config/packages/twig.yaml")]
	twig := symfonyYAMLValue(cfg.value, "twig")
	if symfonyYAMLValue(twig, "autoescape_service") != nil {
		return "unknown"
	}
	node := symfonyYAMLValue(twig, "autoescape")
	if node == nil {
		return "name"
	}
	if node.Kind != yaml.ScalarNode {
		return "unknown"
	}
	switch strings.ToLower(node.Value) {
	case "name", "html":
		return strings.ToLower(node.Value)
	case "false":
		return "off"
	}
	return "unknown"
}

// twigAutoescapeTag reads the strategy of an {% autoescape %} block.
// https://twig.symfony.com/doc/3.x/tags/autoescape.html
func twigAutoescapeTag(argument string) string {
	switch strings.Trim(argument, `'" `) {
	case "", "html", "true":
		return "html"
	case "false":
		return "off"
	}
	return "unknown"
}

// twigLocalURL reports a literal URL prefix that fixes the scheme of whatever
// follows it: a relative reference with a path, query or fragment delimiter
// before any colon, or an http(s) URL whose host is complete.
func twigLocalURL(prefix string) bool {
	if strings.HasPrefix(prefix, "//") {
		return false
	}
	lower := strings.ToLower(prefix)
	for _, scheme := range []string{"http://", "https://"} {
		if host, ok := strings.CutPrefix(lower, scheme); ok {
			return strings.Contains(host, "/")
		}
	}
	delimiter := strings.IndexAny(prefix, "/?#")
	colon := strings.Index(prefix, ":")
	return delimiter >= 0 && (colon < 0 || delimiter < colon)
}

// twigURLProtection judges HTML-escaped output in a URL attribute. HTML
// escaping keeps the value inside its quoted attribute but does not choose
// the URL scheme, so the answer depends on the literal text before the value.
func twigURLProtection(markup, expressionPrefix string) (protection, reason string) {
	tag, attribute, quote, literal, ok := parse.HTMLAttributeValue(markup)
	if !ok || quote == "" {
		return "unknown", ""
	}
	prefix := literal + expressionPrefix
	switch tag {
	case "a", "area", "img", "video", "audio", "source", "track", "form", "button", "input":
		if twigLocalURL(prefix) {
			return "encoded", "The Twig output is HTML-escaped inside a quoted URL attribute, after the literal prefix " + strconv.Quote(prefix) + " that fixes the URL scheme."
		}
	}
	if prefix != "" {
		return "unknown", ""
	}
	switch {
	case attribute == "href" && (tag == "a" || tag == "area"), attribute == "action" && tag == "form",
		attribute == "formaction", attribute == "src" && (tag == "iframe" || tag == "frame" || tag == "script" || tag == "embed"):
		return "raw", "The value is the whole URL of a " + tag + " " + attribute + " attribute. HTML escaping does not restrict its scheme, so a script URL runs."
	}
	return "unknown", ""
}

func (t *twigScope) output(expr string, at analysis.Evidence, markup, autoescape string, markupContext analysis.Evidence) {
	v, mode := t.eval(expr, at)
	t.flow.diagnosticTemplateOutput(at, t.call, v)
	v.deps = slices.DeleteFunc(slices.Clone(v.deps), phpTypedStorageField)
	if len(v.deps) == 0 {
		return
	}
	context := parse.HTMLOutputContext(markup)
	protection, reason := "unknown", ""
	switch {
	case autoescape == "name" && !strings.HasSuffix(at.Span.File, ".html.twig"):
		v.gaps = append(v.gaps, analysis.Gap{Kind: "render_protection_unresolved", Detail: "Template does not establish HTML autoescaping", At: at.Span})
	case autoescape == "off" && mode == "auto" || mode == "raw":
		protection = "raw"
	case autoescape == "unknown" && mode == "auto":
		v.gaps = append(v.gaps, analysis.Gap{Kind: "render_protection_unresolved", Detail: "The Twig autoescape strategy is not HTML or is unresolved", At: at.Span})
	case mode == "unknown":
	case mode == "js" && context == "script", mode == "css" && context == "style",
		mode == "url" && context == "url", mode == "html_attr" && context == "html_attribute":
		protection = "encoded"
	case (mode == "html" || mode == "auto") && (context == "html_text" || context == "html_attribute"):
		protection = "encoded"
	case (mode == "html" || mode == "auto") && context == "url":
		protection, reason = twigURLProtection(markup, v.prefix)
	}
	for _, gap := range v.gaps {
		if gap.Kind == "doctrine_naming_unresolved" {
			v.gaps = append(v.gaps, analysis.Gap{Kind: "storage_origin_unresolved", Detail: "Doctrine field storage key is unresolved", At: at.Span})
			break
		}
	}
	if prior, ok := t.recorded[at.Span]; ok {
		// The same inclusion can render more than once under this action. Preserve
		// all dependencies and protections in its one source-backed sink record.
		u := &t.flow.report.Uses[prior]
		for _, dep := range v.deps {
			u.XSS.Paths = append(u.XSS.Paths, analysis.XSSPath{Dependency: len(u.Dependencies), Protection: protection, OutputContext: context})
			u.Dependencies = append(u.Dependencies, dep.dep)
		}
		u.Context = phpMergeEvidence(u.Context, t.flow.context)
		u.Gaps = phpMergeGaps(u.Gaps, v.gaps)
		if protection == "raw" || protection == "unknown" && u.XSS.Protection != "raw" {
			u.XSS.Protection = protection
		}
		return
	}
	before := len(t.flow.report.Uses)
	t.flow.recordXSS(at, phpProtect(v, protection), context, nil)
	if len(t.flow.report.Uses) == before {
		return
	}
	t.recorded[at.Span] = before
	u := &t.flow.report.Uses[before]
	u.APIModel = analysispacks.XSSContract("twig-html-output-v1", "")
	u.XSS.Protection = protection
	for i := range u.XSS.Paths {
		u.XSS.Paths[i].Protection = protection
	}
	if protection == "encoded" {
		u.XSS.ProtectionReason = "The Twig output uses encoding for the established output context."
	}
	if protection == "unknown" {
		u.XSS.ProtectionReason = "The Twig operation or output context leaves encoding unresolved."
	}
	if reason != "" {
		u.XSS.ProtectionReason = reason
	}
	// The interpolation alone does not show where it lands. The surrounding
	// markup is the evidence for the output context.
	u.Context = append(u.Context, markupContext)
	if context == "url" && v.prefix != "" {
		u.Context = append(u.Context, analysis.Evidence{Kind: "render_literal_prefix", Text: v.prefix, Span: at.Span, SHA256: at.SHA256})
	}
}
