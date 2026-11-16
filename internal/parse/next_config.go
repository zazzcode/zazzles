package parse

import (
	"regexp"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
)

type nextRewrite struct {
	source, destination string
	evidence            analysis.Evidence
}

// nextConfigFacts are the literal parts of next.config the adapter reads.
type nextConfigFacts struct {
	module     *sourceModule
	object     *sitter.Node
	rewrites   []nextRewrite
	hasHeaders bool
	basePath   string
	gaps       []analysis.Gap
}

// nextConfig reads the project's next.config: a literal object exported by
// default, directly or through one top-level const. Anything else is a gap and
// yields no aliases.
func (s *moduleSet) nextConfig(p *nextProject) *nextConfigFacts {
	if p == nil || p.config == "" {
		return nil
	}
	if s.nextConfigs == nil {
		s.nextConfigs = map[string]*nextConfigFacts{}
	}
	if c, ok := s.nextConfigs[p.config]; ok {
		return c
	}
	c := &nextConfigFacts{}
	s.nextConfigs[p.config] = c
	m, err := s.load(p.config)
	if err != nil || m.tree.RootNode().HasError() {
		return c
	}
	c.module = m
	obj := unwrapTS(defaultExport(m))
	if obj == nil {
		// module.exports = {...}
		root := m.tree.RootNode()
		for i := uint(0); i < root.NamedChildCount(); i++ {
			st := root.NamedChild(i)
			if st.Kind() == "expression_statement" && st.NamedChildCount() == 1 && st.NamedChild(0).Kind() == "assignment_expression" {
				a := st.NamedChild(0)
				if l := a.ChildByFieldName("left"); l != nil && l.Utf8Text(m.src) == "module.exports" {
					obj = unwrapTS(a.ChildByFieldName("right"))
					if obj != nil && obj.Kind() == "identifier" {
						obj = unwrapTS(topVariable(m, obj.Utf8Text(m.src)))
					}
				}
			}
		}
	}
	if obj == nil || obj.Kind() != "object" {
		c.gaps = append(c.gaps, analysis.Gap{Kind: "next_config_unresolved", Detail: "next.config does not export a literal object", At: spanOf(m.file, m.tree.RootNode())})
		return c
	}
	c.object = obj
	if bp, ok := stringLiteral(property(obj, "basePath", m.src), m.src); ok {
		c.basePath = bp
	}
	c.hasHeaders = nextConfigMember(obj, "headers", m.src) != nil
	if rw := nextConfigMember(obj, "rewrites", m.src); rw != nil {
		var arr *sitter.Node
		if isFunction(rw) || rw.Kind() == "method_definition" {
			body := rw.ChildByFieldName("body")
			if body != nil && body.Kind() == "statement_block" {
				for i := uint(0); i < body.NamedChildCount(); i++ {
					if st := body.NamedChild(i); st.Kind() == "return_statement" && st.NamedChildCount() == 1 {
						arr = unwrapTS(st.NamedChild(0))
					}
				}
			} else if body != nil {
				arr = unwrapTS(body)
			}
		}
		if arr == nil || arr.Kind() != "array" {
			c.gaps = append(c.gaps, analysis.Gap{Kind: "next_config_unresolved", Detail: "rewrites() does not return a literal array", At: spanOf(m.file, rw)})
		} else {
			for i := uint(0); i < arr.NamedChildCount(); i++ {
				item := arr.NamedChild(i)
				src, ok1 := stringLiteral(property(item, "source", m.src), m.src)
				dst, ok2 := stringLiteral(property(item, "destination", m.src), m.src)
				if ok1 && ok2 && strings.HasPrefix(dst, "/") {
					c.rewrites = append(c.rewrites, nextRewrite{source: src, destination: dst, evidence: m.evidence("next_rewrite", item)})
				}
			}
		}
	}
	return c
}

// nextConfigMember finds a config member that is a pair value or a method.
func nextConfigMember(obj *sitter.Node, key string, src []byte) *sitter.Node {
	if v := property(obj, key, src); v != nil {
		return v
	}
	for i := uint(0); i < obj.NamedChildCount(); i++ {
		c := obj.NamedChild(i)
		if c.Kind() == "method_definition" {
			if n := c.ChildByFieldName("name"); n != nil && n.Utf8Text(src) == key {
				return c
			}
		}
	}
	return nil
}

// nextMiddleware is the project's root middleware (or proxy) and its matcher.
type nextMiddleware struct {
	module   *sourceModule
	fn       *sitter.Node
	matchers []string
	all      bool // no matcher: every path
	gaps     []analysis.Gap
}

func (s *moduleSet) nextMiddlewareFor(p *nextProject) *nextMiddleware {
	if p == nil || p.middleware == "" {
		return nil
	}
	if s.nextMiddlewares == nil {
		s.nextMiddlewares = map[string]*nextMiddleware{}
	}
	if mw, ok := s.nextMiddlewares[p.middleware]; ok {
		return mw
	}
	mw := &nextMiddleware{}
	s.nextMiddlewares[p.middleware] = mw
	m, err := s.load(p.middleware)
	if err != nil || m.tree.RootNode().HasError() {
		return mw
	}
	mw.module = m
	for _, e := range s.nextExports(m, 0) {
		if e.name == "middleware" || e.name == "proxy" || (e.name == "default" && mw.fn == nil) {
			if r := s.nextHandler(m, e.value, 0); r.fn != nil {
				mw.fn = r.fn
			}
		}
	}
	cfg := unwrapTS(topVariable(m, "config"))
	if cfg == nil || cfg.Kind() != "object" {
		mw.all = true
		return mw
	}
	matcher := unwrapTS(property(cfg, "matcher", m.src))
	if matcher == nil {
		mw.all = true
		return mw
	}
	var items []*sitter.Node
	if matcher.Kind() == "array" {
		for i := uint(0); i < matcher.NamedChildCount(); i++ {
			items = append(items, matcher.NamedChild(i))
		}
	} else {
		items = []*sitter.Node{matcher}
	}
	for _, it := range items {
		if text, ok := stringLiteral(it, m.src); ok {
			mw.matchers = append(mw.matchers, text)
			continue
		}
		if it.Kind() == "object" {
			if text, ok := stringLiteral(property(it, "source", m.src), m.src); ok && property(it, "has", m.src) == nil && property(it, "missing", m.src) == nil {
				mw.matchers = append(mw.matchers, text)
				continue
			}
		}
		mw.gaps = append(mw.gaps, analysis.Gap{Kind: "next_matcher_unresolved", Detail: "middleware matcher entry is not a literal path or has has/missing conditions", At: spanOf(m.file, it)})
	}
	return mw
}

var matcherParam = regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)([*+?]?)`)

// nextMatcherRegexp converts the documented path-to-regexp subset. ok is false
// for explicit regex groups, which stay unresolved rather than guessed.
func nextMatcherRegexp(matcher string) (*regexp.Regexp, bool) {
	if strings.ContainsAny(matcher, "()[]{}\\^$|") {
		return nil, false
	}
	var b strings.Builder
	b.WriteString("^")
	last := 0
	for _, loc := range matcherParam.FindAllStringSubmatchIndex(matcher, -1) {
		lit := matcher[last:loc[0]]
		mod := matcher[loc[4]:loc[5]]
		if mod == "*" || mod == "?" {
			lit = strings.TrimSuffix(lit, "/")
			b.WriteString(regexp.QuoteMeta(lit))
			if mod == "*" {
				b.WriteString(`(?:/[^/]+)*`)
			} else {
				b.WriteString(`(?:/[^/]+)?`)
			}
		} else {
			b.WriteString(regexp.QuoteMeta(lit))
			if mod == "+" {
				b.WriteString(`[^/]+(?:/[^/]+)*`)
			} else {
				b.WriteString(`[^/]+`)
			}
		}
		last = loc[1]
	}
	b.WriteString(regexp.QuoteMeta(matcher[last:]))
	b.WriteString("/?$")
	re, err := regexp.Compile(b.String())
	return re, err == nil
}

// nextPatternSample turns an entry pattern into a representative concrete path.
func nextPatternSample(pattern string) string {
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ":") {
			parts[i] = "x"
		}
	}
	return strings.Join(parts, "/")
}

// nextMiddlewareStages attaches the root middleware as a lifecycle stage when
// its matcher covers the entry pattern. Middleware checks are authorization
// context, never destination controls.
func (s *moduleSet) nextMiddlewareStages(p *nextProject, pattern, surface string) []analysis.InputStage {
	mw := s.nextMiddlewareFor(p)
	if mw == nil || mw.module == nil || mw.fn == nil {
		return nil
	}
	covered := mw.all
	for _, m := range mw.matchers {
		re, ok := nextMatcherRegexp(m)
		if !ok {
			continue
		}
		covered = covered || re.MatchString(nextPatternSample(pattern)) || re.MatchString(pattern)
	}
	if !covered {
		return nil
	}
	body := mw.fn.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	return []analysis.InputStage{{Name: "next_middleware", Order: 5, Scope: "project", Evidence: mw.module.evidence("middleware_handler", body)}}
}

// nextMiddlewareGaps returns matcher gaps that may apply to every entry.
func (s *moduleSet) nextMiddlewareGaps(p *nextProject) []analysis.Gap {
	mw := s.nextMiddlewareFor(p)
	if mw == nil {
		return nil
	}
	return mw.gaps
}

// nextChainEvidence supplies the bounded lifecycle a Next.js entry receives:
// verified wrappers (authorization context), middleware stages that the matcher
// attaches, and the helper definitions the handler calls.
func (s *moduleSet) nextChainEvidence(c *nodeHTTPContext) []analysis.Evidence {
	out := []analysis.Evidence{}
	for _, st := range c.stages {
		out = append(out, st.Evidence)
	}
	return out
}
