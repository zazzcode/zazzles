package langjs

import (
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// Configuration for Express (lane decision D-9). Existing check identifiers
// only:
//
//   - directory_listing (CWE-548): a serve-index middleware passed to app.use.
//     serve-index serves a listing of the directory it is given
//     (https://github.com/expressjs/serve-index#readme). The facts joined are
//     the mount path, the directory argument, the mount's access record and the
//     middleware before it on the same call.
//   - session_cookie_script_readable (CWE-1004) and
//     session_cookie_insecure_transport (CWE-614): the httpOnly and secure
//     options of the cookie that express-session and cookie-session send.
//     Only an explicit false is recorded; an absent option and a true are not.
//
// A res.cookie call is not recorded: that a cookie carries the session is not
// established by its name.

// configurationCandidates records the D-9 settings of every selected module.
func (s *moduleSet) configurationCandidates(out *analysis.AnalysisReport, selected []string) {
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
			if fn == nil || args == nil || fn.Kind() != "member_expression" {
				return
			}
			obj, prop := fn.ChildByFieldName("object"), fn.ChildByFieldName("property")
			if obj == nil || prop == nil || prop.Utf8Text(m.src) != "use" || obj.Kind() != "identifier" ||
				!receiverUsable(m, call, obj.Utf8Text(m.src)) {
				return
			}
			receiver := obj.Utf8Text(m.src)
			for i := uint(0); i < args.NamedChildCount(); i++ {
				arg := args.NamedChild(i)
				switch {
				case libraryCall(m, arg, "serve-index", ""):
					s.directoryListing(out, m, call, arg, i, receiver)
				case libraryCall(m, arg, "express-session", ""):
					if opts := argumentObject(m, arg, 0); opts != nil {
						if cookie := resolvedProperty(m, opts, "cookie"); cookie != nil {
							s.cookieSettings(out, m, call, arg, cookie, receiver)
						}
					}
				case libraryCall(m, arg, "cookie-session", ""):
					if opts := argumentObject(m, arg, 0); opts != nil {
						s.cookieSettings(out, m, call, arg, opts, receiver)
					}
				}
			}
		})
	}
}

func (s *moduleSet) directoryListing(out *analysis.AnalysisReport, m *sourceModule, use, listing *sitter.Node, index uint, receiver string) {
	args := use.ChildByFieldName("arguments")
	path, hasPath := stringLiteral(args.NamedChild(0), m.src)
	first, rel := uint(0), "/"
	pathNode := use
	if hasPath {
		first, rel, pathNode = 1, path, args.NamedChild(0)
	}
	setting := m.evidence("setting", listing)
	joined := []analysis.Evidence{m.evidence("mount_path", pathNode)}
	if !hasPath {
		joined[0].ModelText = "The middleware is registered with no path, so it applies to every request path."
	}
	if dir := listing.ChildByFieldName("arguments"); dir != nil && dir.NamedChildCount() > 0 {
		joined = append(joined, m.evidence("directory", dir.NamedChild(0)))
		if contents, ok := s.directoryContents(m, dir.NamedChild(0)); ok {
			joined = append(joined, contents)
		}
		joined = append(joined, s.directoryReferences(m, dir.NamedChild(0))...)
	}
	access := s.expressAccessFor(m, use, rel, nil, first, index)
	mount := m.evidence("mount_access", use)
	mount.ModelText = "authentication: " + access.Authentication
	if len(access.Sources) > 0 {
		mount.ModelText += "; established by " + access.Sources[len(access.Sources)-1].Text
	}
	joined = append(joined, mount)
	for i := first; i < index; i++ {
		joined = append(joined, s.mountMiddleware(m, args.NamedChild(i)))
	}
	s.recordConfiguration(out, m, use, receiver, &analysis.ConfigurationFacts{
		Check: analysis.CheckDirectoryListing, Setting: setting, Value: "serve-index", Scope: rel, Joined: joined,
	}, m.evidence("scope", use))
}

// mountMiddleware is the evidence of a middleware argument: its function body
// when it resolves to one, otherwise the argument.
func (s *moduleSet) mountMiddleware(m *sourceModule, arg *sitter.Node) analysis.Evidence {
	if hm, body, _, gaps := s.handler(m, arg); body != nil && len(gaps) == 0 {
		return hm.evidence("mount_middleware", body)
	}
	return m.evidence("mount_middleware", arg)
}

// cookieSettings records an explicit false httpOnly or secure option of the
// cookie options object.
func (s *moduleSet) cookieSettings(out *analysis.AnalysisReport, m *sourceModule, use, middleware, options *sitter.Node, receiver string) {
	for _, st := range []struct{ option, check string }{
		{"httpOnly", analysis.CheckSessionCookieScript},
		{"secure", analysis.CheckSessionCookieTransport},
	} {
		value := resolvedProperty(m, options, st.option)
		if value == nil {
			continue
		}
		literal := value
		if value.Kind() == "identifier" {
			if v := unwrapTS(topVariable(m, value.Utf8Text(m.src))); v != nil && !bindingReassigned(m, value.Utf8Text(m.src)) {
				literal = v
			}
		}
		if literal.Kind() != "false" {
			continue
		}
		setting := m.evidence("setting", settingNode(literal))
		joined := []analysis.Evidence{m.evidence("session_middleware", middleware)}
		if literal != value {
			joined = append(joined, m.evidence("resolved_value", literal))
		}
		s.recordConfiguration(out, m, use, receiver, &analysis.ConfigurationFacts{
			Check: st.check, Setting: setting, Value: "false", Scope: "session cookie", Joined: joined,
		}, m.evidence("scope", middleware))
	}
}

func settingNode(n *sitter.Node) *sitter.Node {
	if p := n.Parent(); p != nil && p.Kind() == "pair" {
		return p
	}
	return n
}

// argumentObject returns the object literal that is argument i of a call,
// directly or through a constant that is bound to one.
func argumentObject(m *sourceModule, call *sitter.Node, i uint) *sitter.Node {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() <= i {
		return nil
	}
	return objectOf(m, args.NamedChild(i))
}

func objectOf(m *sourceModule, n *sitter.Node) *sitter.Node {
	n = unwrapTS(n)
	if n == nil {
		return nil
	}
	if n.Kind() == "object" {
		return n
	}
	if n.Kind() == "identifier" && !bindingReassigned(m, n.Utf8Text(m.src)) {
		if v := unwrapTS(topVariable(m, n.Utf8Text(m.src))); v != nil && v.Kind() == "object" {
			return v
		}
	}
	return nil
}

// resolvedProperty returns the value of an object literal's property, as the
// object a constant resolves to when the value is one.
func resolvedProperty(m *sourceModule, obj *sitter.Node, name string) *sitter.Node {
	v := property(obj, name, m.src)
	if v == nil {
		return nil
	}
	if o := objectOf(m, v); o != nil && v.Kind() == "identifier" {
		return o
	}
	return v
}

// recordConfiguration emits one candidate riding the entry of the registration.
func (s *moduleSet) recordConfiguration(out *analysis.AnalysisReport, m *sourceModule, use *sitter.Node, receiver string, facts *analysis.ConfigurationFacts, scope analysis.Evidence) {
	entries := s.entriesFor(out, m, use)
	if len(entries) == 0 {
		entries = s.mountEntry(out, m, use, receiver)
	}
	if len(entries) == 0 {
		return
	}
	scope.Kind = "scope"
	// The source file that builds the application is what runs when it starts:
	// the mapping fact the setting_effect question asks for (deployed_file).
	deployed := m.evidence("deployed_file", use)
	deployed.ModelText = "This application source file registers the setting above on the Express application it builds; the application runs this registration when it starts."
	facts.Joined = append(facts.Joined, deployed)
	e := entries[0]
	out.Uses = append(out.Uses, analysis.CandidateUse{
		EntryID: e.ID, Kind: analysis.ConfigurationKind, Sink: facts.Setting, Configuration: facts,
		Gaps:       []analysis.Gap{},
		Assessment: analysis.Assessment{Status: "not_run"},
		Completeness: &analysis.Completeness{
			ClaimKind: "configuration", Required: []string{"setting", "scope"},
			Evidence: map[string][]analysis.Evidence{"setting": {facts.Setting}, "scope": {scope}, "dispatch_binding": {e.Location}},
			Blockers: []analysis.Gap{}, Coverage: []analysis.Gap{},
			Scope: "One allow-listed setting joined to the application facts that give it meaning. The scanner does not decide that the setting is a defect.",
		},
	})
}

// maxListedEntries bounds the names a directory_contents fact carries.
const maxListedEntries = 8

// directoryContents is the D-9 fact of hardening 3: what the listed directory
// holds in the scanned tree. serve-index lists the entries of the directory it
// is given, so the fact names its immediate entries, sorted, at most eight,
// with the total; a subdirectory ends in a slash. The directory argument must
// be a literal relative path inside the scan root, which is read as the
// directory the application starts in.
func (s *moduleSet) directoryContents(m *sourceModule, arg *sitter.Node) (analysis.Evidence, bool) {
	dir, clean, ok := listedRelativeDirectory(m, arg)
	if !ok {
		return analysis.Evidence{}, false
	}
	e := m.evidence("directory_contents", arg)
	entries, err := os.ReadDir(filepath.Join(s.root, clean))
	switch {
	case os.IsNotExist(err):
		e.ModelText = "The directory " + dir + " is not in the scanned tree. What it holds when the application runs is not known from the source."
		return e, true
	case err != nil:
		return analysis.Evidence{}, false
	case len(entries) == 0:
		e.ModelText = "The directory " + dir + " is empty in the scanned tree."
		return e, true
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			name += "/"
		}
		names = append(names, name)
	}
	sort.Strings(names)
	noun, shown := "entries", "its entries: "
	if len(names) == 1 {
		noun, shown = "entry", "its entry: "
	}
	if len(names) > maxListedEntries {
		shown = fmt.Sprintf("the first %d by name: ", maxListedEntries)
		names = names[:maxListedEntries]
	}
	e.ModelText = fmt.Sprintf("The directory %s holds %d %s in the scanned tree; %s%s.", dir, len(entries), noun, shown, strings.Join(names, ", "))
	return e, true
}

// listedRelativeDirectory accepts the directory argument of a listing when it
// is a literal relative path that stays inside the scan root, and returns the
// literal and its cleaned OS-specific form.
func listedRelativeDirectory(m *sourceModule, arg *sitter.Node) (dir, clean string, ok bool) {
	dir, ok = stringLiteral(arg, m.src)
	if !ok || dir == "" || filepath.IsAbs(dir) {
		return "", "", false
	}
	clean = filepath.Clean(filepath.FromSlash(dir))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", "", false
	}
	return dir, clean, true
}

// directoryReferences is specification 23 S-1: every place in the selected
// modules whose path literal is the listed directory or lies under it. A place
// is a string literal (or a template string without substitutions), or a
// path.join or path.resolve call whose arguments are all string literals
// (Node core module path, https://nodejs.org/api/path.html), evaluated as a
// relative path. The evidence is the nearest enclosing object property or
// call. The listing's own directory literal and the serve-index or
// express.static registrations of the same directory are left out (D-2). No
// reference means no evidence, so the record is unchanged.
func (s *moduleSet) directoryReferences(listed *sourceModule, arg *sitter.Node) []analysis.Evidence {
	_, osClean, ok := listedRelativeDirectory(listed, arg)
	if !ok {
		return nil
	}
	dir := filepath.ToSlash(osClean)
	if dir == "." {
		return nil
	}
	type found struct {
		m     *sourceModule
		ctx   *sitter.Node
		value string
	}
	var refs []found
	seen := map[string]bool{}
	for _, m := range s.reachableModules(listed) {
		file := m.file
		var walk func(n *sitter.Node)
		walk = func(n *sitter.Node) {
			var value string
			isRef := false
			switch n.Kind() {
			case "string", "template_string":
				if m == listed && sameNode(n, arg) {
					return
				}
				if v, ok := plainLiteral(m, n); ok && !pathPosition(n, m.src) {
					value, isRef = v, true
				}
			case "call_expression":
				if v, ok := literalPathCall(m, n); ok {
					value, isRef = v, true
				} else if isPathCall(m, n) {
					return // a lone literal inside a call that is not a reference is not read on its own
				}
			}
			if isRef {
				if !withinDirectory(value, dir) || ownRegistration(m, n, value, dir) {
					return
				}
				ctx := enclosingContext(n)
				key := fmt.Sprintf("%s:%d:%d", file, ctx.StartByte(), ctx.EndByte())
				if !seen[key] {
					seen[key] = true
					refs = append(refs, found{m, ctx, value})
				}
				return
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i))
			}
		}
		walk(m.tree.RootNode())
	}
	if len(refs) == 0 {
		return nil
	}
	sort.SliceStable(refs, func(i, j int) bool {
		if refs[i].m.file != refs[j].m.file {
			return refs[i].m.file < refs[j].m.file
		}
		return refs[i].ctx.StartByte() < refs[j].ctx.StartByte()
	})
	total := len(refs)
	if total > maxListedEntries {
		refs = refs[:maxListedEntries]
	}
	out := make([]analysis.Evidence, 0, len(refs))
	for i, r := range refs {
		e := r.m.evidence("directory_reference", r.ctx)
		e.ModelText = fmt.Sprintf("The source refers to paths inside the listed directory %s at %d places; this is %d of %d, the path %s:\n%s", dir, total, i+1, total, r.value, e.ModelText)
		out = append(out, e)
	}
	return out
}

// plainLiteral is the text of a string or of a template string without
// substitutions.
func plainLiteral(m *sourceModule, n *sitter.Node) (string, bool) {
	if n.Kind() == "string" {
		return stringLiteral(n, m.src)
	}
	for i := uint(0); i < n.NamedChildCount(); i++ {
		if n.NamedChild(i).Kind() == "template_substitution" {
			return "", false
		}
	}
	text := n.Utf8Text(m.src)
	if len(text) < 2 {
		return "", false
	}
	return text[1 : len(text)-1], true
}

// pathPosition reports a string that is not a path value: a module source
// (import or require argument) or an object key.
func pathPosition(n *sitter.Node, src []byte) bool {
	p := n.Parent()
	if p == nil {
		return false
	}
	switch p.Kind() {
	case "import_statement", "export_statement":
		return true
	case "pair":
		k := p.ChildByFieldName("key")
		return k != nil && sameNode(k, n)
	case "arguments":
		if c := p.Parent(); c != nil && c.Kind() == "call_expression" {
			if fn := c.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" {
				return fn.Utf8Text(src) == "require" || fn.Kind() == "import"
			}
		}
	}
	return false
}

// isPathCall reports a call of path.join or path.resolve of the Node core
// module, imported as path or node:path.
func isPathCall(m *sourceModule, n *sitter.Node) bool {
	for _, mod := range []string{"path", "node:path"} {
		for _, member := range []string{"join", "resolve"} {
			if libraryCall(m, n, mod, member) {
				return true
			}
		}
	}
	return false
}

// literalPathCall evaluates path.join or path.resolve as a relative path from
// the literal arguments at its start, up to the first argument that is not a
// string literal (D-5). The first argument must be a literal, and an absolute
// result is not a reference. The value is that literal prefix.
func literalPathCall(m *sourceModule, n *sitter.Node) (string, bool) {
	if !isPathCall(m, n) {
		return "", false
	}
	args := n.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	resolve := n.ChildByFieldName("function").ChildByFieldName("property").Utf8Text(m.src) == "resolve"
	var parts []string
	for i := uint(0); i < args.NamedChildCount(); i++ {
		v, ok := plainLiteral(m, args.NamedChild(i))
		if !ok {
			if i == 0 {
				return "", false
			}
			break
		}
		if v == "" {
			continue
		}
		// join keeps a later absolute part relative; resolve restarts at it.
		if strings.HasPrefix(v, "/") && (resolve || len(parts) == 0) {
			return "", false
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return "", false
	}
	return path.Clean(strings.Join(parts, "/")), true
}

// reachableModules is the listing's module and every module it reaches by
// static import, export-from or require of a literal specifier that resolves
// to a scanned module (D-4), in a deterministic order, each once.
func (s *moduleSet) reachableModules(root *sourceModule) []*sourceModule {
	seen := map[string]bool{root.file: true}
	order := []*sourceModule{}
	queue := []*sourceModule{root}
	for len(queue) > 0 {
		m := queue[0]
		queue = queue[1:]
		if m.tree.RootNode().HasError() {
			continue
		}
		order = append(order, m)
		var specs []string
		var walk func(n *sitter.Node)
		walk = func(n *sitter.Node) {
			switch n.Kind() {
			case "import_statement", "export_statement":
				if spec, ok := stringLiteral(n.ChildByFieldName("source"), m.src); ok {
					specs = append(specs, spec)
				}
			case "call_expression":
				if fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments"); fn != nil && args != nil && args.NamedChildCount() == 1 && fn.Kind() == "identifier" && fn.Utf8Text(m.src) == "require" {
					if spec, ok := stringLiteral(args.NamedChild(0), m.src); ok {
						specs = append(specs, spec)
					}
				}
			}
			for i := uint(0); i < n.NamedChildCount(); i++ {
				walk(n.NamedChild(i))
			}
		}
		walk(m.tree.RootNode())
		for _, spec := range specs {
			if t := s.importModule(m, spec); t != nil && !seen[t.file] {
				seen[t.file] = true
				queue = append(queue, t)
			}
		}
	}
	return order
}

// withinDirectory reports a cleaned relative literal that is dir or under it;
// logs-public is not under logs.
func withinDirectory(value, dir string) bool {
	if value == "" || strings.HasPrefix(value, "/") || filepath.IsAbs(value) {
		return false
	}
	v := path.Clean(strings.TrimSuffix(value, "/"))
	return v == dir || strings.HasPrefix(v, dir+"/")
}

// ownRegistration reports a literal (or literal path call) that is the first
// argument of a serve-index or express.static call: another registration of
// the directory, which says nothing the record does not hold (D-2).
func ownRegistration(m *sourceModule, n *sitter.Node, value, dir string) bool {
	if path.Clean(strings.TrimSuffix(value, "/")) != dir {
		return false
	}
	args := n.Parent()
	if args == nil || args.Kind() != "arguments" || args.NamedChildCount() == 0 || !sameNode(args.NamedChild(0), n) {
		return false
	}
	call := args.Parent()
	return call != nil && (libraryCall(m, call, "serve-index", "") || libraryCall(m, call, "express", "static"))
}

// enclosingContext is the nearest object property or call around a reference.
func enclosingContext(n *sitter.Node) *sitter.Node {
	for p := n.Parent(); p != nil; p = p.Parent() {
		if p.Kind() == "pair" || p.Kind() == "call_expression" {
			return p
		}
	}
	return n
}
