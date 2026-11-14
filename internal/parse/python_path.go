package parse

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
	"github.com/zazzcode/zazzles/internal/analysis"
	"github.com/zazzcode/zazzles/internal/analysispacks"
)

// pyPathlibOps are the verified pathlib.Path read/write methods: the receiver
// carries the path; text, bytes, encoding and mode arguments are separate.
var pyPathlibOps = map[string]struct{ role, content string }{
	"read_text": {"read", ""}, "read_bytes": {"read", ""}, "write_text": {"write", "data"}, "write_bytes": {"write", "data"}, "open": {"", ""},
}

var pyPathObjectNames = map[string]bool{"pathlib.Path": true, "pathlib.PurePath": true, "pathlib.PosixPath": true, "pathlib.PurePosixPath": true}

// pyModeledPathCalls are qualified calls modeled as path transformations. None
// of them checks containment.
var pyModeledPathCalls = map[string]bool{
	"os.path.join": true, "os.path.abspath": true, "os.path.normpath": true, "os.path.realpath": true, "os.path.basename": true, "os.path.dirname": true,
	"os.path.relpath": true, "os.path.commonpath": true, "os.path.isabs": true, "os.path.expanduser": true, "os.path.normcase": true,
	"posixpath.join": true, "posixpath.abspath": true, "posixpath.normpath": true, "posixpath.realpath": true, "posixpath.basename": true, "posixpath.dirname": true,
	"urllib.parse.unquote": true, "urllib.parse.unquote_plus": true, "os.getcwd": true, "werkzeug.utils.secure_filename": true,
}

// pyPathMethods are pathlib receiver methods that return another path object.
var pyPathMethods = map[string]bool{"resolve": true, "joinpath": true, "absolute": true, "with_name": true, "with_suffix": true, "expanduser": true, "relative_to": true, "is_relative_to": true}

// pyArchiveOpens are the verified archive/compressed-file opens whose first
// argument is the file name; the value is the keyword that names it.
var pyArchiveOpens = map[string]string{
	"tarfile.open": "name", "tarfile.TarFile": "name", "tarfile.TarFile.open": "name",
	"bz2.open": "filename", "bz2.BZ2File": "filename", "gzip.open": "filename", "gzip.GzipFile": "filename",
	"lzma.open": "filename", "lzma.LZMAFile": "filename",
}

func pyPathModule(q string) bool {
	return strings.HasPrefix(q, "pathlib.") || strings.HasPrefix(q, "os.path.") || strings.HasPrefix(q, "posixpath.") || q == "io.open"
}

type pyPathBuilder struct {
	f       *pythonFlow
	facts   *analysis.PathFacts
	deps    []pythonDep
	context []analysis.Evidence
	gaps    []analysis.Gap
	names   map[string]bool
	request bool
}

func (b *pyPathBuilder) operand(slot, kind string, n *sitter.Node, v pythonValue) {
	o := analysis.PathOperand{Slot: slot}
	if text, ok := pyLiteral(b.f.module, n); ok {
		o.Constant = text
	} else {
		o.Dynamic = true
	}
	o.Context = append(o.Context, len(b.context))
	b.context = append(b.context, b.f.module.evidence(kind, n))
	for _, d := range v.deps {
		if slot == analysis.PathSlotFile && !requestOrigin(d.dep) {
			continue // a stored, file or API value is not a request field
		}
		d.dep.SinkSlot = slot
		idx := len(b.deps)
		o.Dependencies = append(o.Dependencies, idx)
		if slot == analysis.PathSlotFile {
			b.facts.Paths = append(b.facts.Paths, analysis.PathFlow{Dependency: idx, Operand: slot, Protection: "raw", Transforms: pathTransforms(d.dep), Root: pathRoot(d.dep)})
			b.request = true
			b.names[d.container+"."+d.key] = true
			b.names[d.dep.Source.Text] = true
			for _, name := range commandDepNames(d.dep) {
				b.names[name] = true
			}
		}
		b.deps = append(b.deps, d)
	}
	if slot == analysis.PathSlotFile {
		pyWalk(n, func(c *sitter.Node) {
			if c.Kind() == "identifier" {
				b.names[pyText(b.f.module, c)] = true
			}
		})
		b.gaps = append(b.gaps, v.gaps...)
	}
	b.facts.Operands = append(b.facts.Operands, o)
}

// openRole reads the mode of open/io.open/Path.open: a literal selects read or
// write, a dynamic mode is unknown, and the default is read.
func (f *pythonFlow) openRole(call *sitter.Node, modeNode *sitter.Node) string {
	if modeNode == nil {
		return "read"
	}
	mode, ok := pyLiteral(f.module, modeNode)
	if !ok {
		return "unknown"
	}
	if strings.ContainsAny(mode, "wax+") {
		return "write"
	}
	return "read"
}

// pathOperation resolves the called function or method to a verified read/write
// of the supported open/io.open/pathlib contracts. Shadowing, imports, aliases
// and local modules are verified; a wrapper or fake object is not.
func (f *pythonFlow) pathOperation(call, fn *sitter.Node, receiver pythonValue, object *sitter.Node, method string) (op, contract, role string, path *sitter.Node, content *sitter.Node, evidence []analysis.Evidence, ok bool) {
	m := f.module
	name := pyText(m, fn)
	positional := pyArgs(call)
	argument := func(index int, keyword string) *sitter.Node {
		if len(positional) > index {
			return positional[index]
		}
		return pyKeywordIn(m, call, keyword)
	}
	switch {
	case fn.Kind() == "identifier" && name == "open" && f.builtin("open"):
		path = argument(0, "file")
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		return "open", analysispacks.PythonOpenContract, f.openRole(call, argument(1, "mode")), path, nil, []analysis.Evidence{m.evidence("sink_binding", fn)}, true
	case f.qualified(name) == "io.open":
		if f.set.commandTampered(m, "io") {
			return
		}
		path = argument(0, "file")
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		root := strings.Split(name, ".")[0]
		evidence = []analysis.Evidence{}
		if imp, found := f.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		} else if imp, found := m.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		}
		evidence = append(evidence, m.evidence("sink_binding", fn))
		return "io.open", analysispacks.PythonOpenContract, f.openRole(call, argument(1, "mode")), path, nil, evidence, true
	case f.qualified(name) == "os.remove" || f.qualified(name) == "os.unlink":
		q := f.qualified(name)
		if f.set.commandTampered(m, "os") {
			return
		}
		path = argument(0, "path")
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		root := strings.Split(name, ".")[0]
		evidence = []analysis.Evidence{}
		if imp, found := f.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		} else if imp, found := m.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		}
		return q, analysispacks.PythonOSFileContract, "delete", path, nil, append(evidence, m.evidence("sink_binding", fn)), true
	case f.qualified(name) == "flask.send_file" || f.qualified(name) == "flask.send_from_directory":
		q := f.qualified(name)
		if f.set.commandTampered(m, "flask") {
			return
		}
		if q == "flask.send_file" {
			path = argument(0, "path_or_file")
		} else if path = argument(1, "path"); path == nil {
			path = pyKeywordIn(m, call, "filename")
		}
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		root := strings.Split(name, ".")[0]
		evidence = []analysis.Evidence{}
		if imp, found := f.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		} else if imp, found := m.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		}
		return q, analysispacks.FlaskSendContract, "read", path, nil, append(evidence, m.evidence("sink_binding", fn)), true
	case pyArchiveOpens[f.qualified(name)] != "":
		q := f.qualified(name)
		if f.set.commandTampered(m, strings.Split(q, ".")[0]) {
			return
		}
		path = argument(0, pyArchiveOpens[q])
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		root := strings.Split(name, ".")[0]
		evidence = []analysis.Evidence{}
		if imp, found := f.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		} else if imp, found := m.imports[root]; found {
			evidence = append(evidence, m.evidence("sink_binding", imp.node))
		}
		evidence = append(evidence, m.evidence("sink_binding", fn))
		return q, analysispacks.PythonArchiveContract, f.openRole(call, argument(1, "mode")), path, nil, evidence, true
	case method == "save" && object != nil && fn.Kind() == "attribute" && uploadReceiver(receiver):
		path = argument(0, "dst")
		if path == nil || path.Kind() == "list_splat" {
			return
		}
		return "werkzeug.FileStorage.save", analysispacks.PythonSaveContract, "write", path, nil, []analysis.Evidence{m.evidence("sink_binding", object), m.evidence("sink_binding", fn)}, true
	case receiver.binding == "pathlib_path" && object != nil:
		spec, known := pyPathlibOps[method]
		if !known || f.set.commandTampered(m, "pathlib") {
			return
		}
		role = spec.role
		if method == "open" {
			role = f.openRole(call, argument(0, "mode"))
		}
		if spec.content != "" {
			content = argument(0, "data")
		}
		return "pathlib.Path." + method, analysispacks.PythonPathlibContract, role, object, content, []analysis.Evidence{m.evidence("sink_binding", object)}, true
	}
	return
}

// uploadReceiver reports a value taken from request.files: a werkzeug FileStorage.
func uploadReceiver(v pythonValue) bool {
	if len(v.deps) == 0 {
		return false
	}
	for _, d := range v.deps {
		if d.container != "files" {
			return false
		}
	}
	return true
}

var sanitizerCallee = regexp.MustCompile(`^\s*([A-Za-z_][\w.]*)\s*\(`)

// verifiedSanitizers returns the transfer evidence of each verified
// werkzeug.utils.secure_filename call on the dependency's value chain; a local
// function of the same name is not one.
func (f *pythonFlow) verifiedSanitizers(d analysis.Dependency) []analysis.Evidence {
	var out []analysis.Evidence
	for _, e := range d.Transfers {
		if transformKind(e) != analysis.PathTransformSanitize {
			continue
		}
		if m := sanitizerCallee.FindStringSubmatch(e.Text); len(m) == 2 && f.qualified(m[1]) == "werkzeug.utils.secure_filename" {
			out = append(out, e)
		}
	}
	return out
}

// pathCall records a path_traversal_candidate when request data reaches the
// path operand of a verified filesystem call. It is additive: the call is then
// handled exactly as before.
func (f *pythonFlow) pathCall(call, fn *sitter.Node, receiver pythonValue, object *sitter.Node, method string) {
	op, contract, role, pathNode, contentNode, binding, ok := f.pathOperation(call, fn, receiver, object, method)
	if !ok {
		return
	}
	m := f.module
	b := &pyPathBuilder{f: f, names: map[string]bool{}, facts: &analysis.PathFacts{Operation: op, ContractID: contract, Platform: "posix", Role: role,
		Operands: []analysis.PathOperand{}, Paths: []analysis.PathFlow{}, Guards: []analysis.PathGuard{}}}
	args := call.ChildByFieldName("arguments")
	for i := uint(0); args != nil && i < args.NamedChildCount(); i++ {
		if c := args.NamedChild(i); c.Kind() == "list_splat" || c.Kind() == "dictionary_splat" {
			b.gaps = append(b.gaps, f.gap("path_spread_unresolved", "*args/**kwargs in a filesystem call are not modeled", c))
		}
	}
	b.operand(analysis.PathSlotFile, "path_operand", pathNode, f.quiet(pathNode))
	if !b.request {
		return
	}
	if contentNode != nil {
		b.operand(analysis.PathSlotContent, "path_content", contentNode, f.quiet(contentNode))
	}
	id := fmt.Sprintf("use:%s:%s:%d:%s", f.invocation.ID, m.file, call.StartByte(), "path_traversal_candidate")
	for _, existing := range f.report.Uses {
		if existing.ID == id {
			return // several syntactic paths reach one call in one invocation; one record
		}
	}
	var all pythonValue
	for _, d := range b.deps {
		all.deps = append(all.deps, d)
	}
	all.gaps = b.gaps
	u := f.addUse("path_traversal_candidate", call, all)
	u.Path = b.facts
	u.APIModel = analysispacks.PathContract(contract)
	u.Dependencies = make([]analysis.Dependency, len(b.deps))
	for i, d := range b.deps {
		u.Dependencies[i] = d.dep
	}
	u.Context = append(u.Context, binding...)
	base := len(u.Context)
	u.Context = append(u.Context, b.context...)
	for i := range u.Path.Operands {
		for j := range u.Path.Operands[i].Context {
			u.Path.Operands[i].Context[j] += base
		}
	}
	info := newPathGuardInfo()
	guards := f.pythonPathGuards(call, u, b.names, info)
	if op == "flask.send_from_directory" {
		// The library joins the path to the directory with safe_join and rejects an
		// escape; that holds only for a directory that is not request-derived.
		directory := pyKeywordIn(m, call, "directory")
		if args := pyArgs(call); directory == nil && len(args) > 0 {
			directory = args[0]
		}
		if directory != nil && len(f.quiet(directory).deps) == 0 {
			ev := m.evidence("framework_root", directory)
			covered := map[int]bool{}
			for i, d := range u.Dependencies {
				if d.SinkSlot == analysis.PathSlotFile {
					covered[i] = true
				}
			}
			info.note(ev, analysis.PathGuardFrameworkRoot, covered)
			guards = append(guards, ev)
		}
	}
	for i, d := range u.Dependencies {
		if d.SinkSlot != analysis.PathSlotFile {
			continue
		}
		sanitizers := f.verifiedSanitizers(d)
		for _, e := range sanitizers {
			info.note(e, analysis.PathGuardComponentSanitizer, map[int]bool{i: true})
			guards = append(guards, e)
		}
		for j := range u.Path.Paths {
			if u.Path.Paths[j].Dependency != i {
				continue
			}
			kept := u.Path.Paths[j].Transforms[:0:0]
			for _, t := range u.Path.Paths[j].Transforms {
				if t != analysis.PathTransformSanitize || len(sanitizers) > 0 {
					kept = append(kept, t)
				}
			}
			u.Path.Paths[j].Transforms = kept
		}
	}
	guardIndex := []int{}
	for _, g := range guards {
		guardIndex = append(guardIndex, len(u.Context))
		u.Context = append(u.Context, g)
	}
	f.completePythonPath(u, call, all, guards, guardIndex, b.names, info)
}

// pyConstantCollection reports a module-level list, tuple, set or dict (or a
// set/frozenset/tuple/list call of one) made only of string literals.
func pyConstantCollection(m *pythonModule, name string) bool {
	node := m.vars[strings.TrimSpace(name)]
	if node == nil || pythonReassigned(m, strings.TrimSpace(name)) {
		return false
	}
	if node.Kind() == "call" {
		fn := pyText(m, node.ChildByFieldName("function"))
		args := pyArgs(node)
		if (fn != "set" && fn != "frozenset" && fn != "tuple" && fn != "list") || len(args) != 1 {
			return false
		}
		node = args[0]
	}
	switch node.Kind() {
	case "set", "list", "tuple":
		for i := uint(0); i < node.NamedChildCount(); i++ {
			if c := node.NamedChild(i); c.Kind() != "string" && c.Kind() != "comment" {
				return false
			}
		}
		return node.NamedChildCount() > 0
	case "dictionary":
		for i := uint(0); i < node.NamedChildCount(); i++ {
			if c := node.NamedChild(i); c.Kind() == "pair" {
				if key := c.ChildByFieldName("key"); key == nil || key.Kind() != "string" {
					return false
				}
			}
		}
		return node.NamedChildCount() > 0
	}
	return false
}

// pyConstantPath reports an expression built only from literals, __file__ and
// modeled path operations over those: a trusted base.
func (f *pythonFlow) pyConstantPath(m *pythonModule, n *sitter.Node, depth int) bool {
	if n == nil || depth > 6 {
		return false
	}
	switch n.Kind() {
	case "string":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if c := n.NamedChild(i); c.Kind() == "interpolation" && (c.NamedChildCount() == 0 || !f.pyConstantPath(m, c.NamedChild(0), depth+1)) {
				return false
			}
		}
		return true
	case "integer", "float":
		return true
	case "parenthesized_expression":
		return n.NamedChildCount() > 0 && f.pyConstantPath(m, n.NamedChild(0), depth+1)
	case "binary_operator":
		return f.pyConstantPath(m, n.ChildByFieldName("left"), depth+1) && f.pyConstantPath(m, n.ChildByFieldName("right"), depth+1)
	case "attribute":
		switch pyText(m, n.ChildByFieldName("attribute")) {
		case "parent", "name", "stem", "suffix", "sep":
			return f.pyConstantPath(m, n.ChildByFieldName("object"), depth+1) || strings.HasSuffix(pyText(m, n), "os.sep")
		}
		return false
	case "identifier":
		name := pyText(m, n)
		if name == "__file__" {
			return true
		}
		if _, local := f.env[name]; local {
			return false
		}
		if v := m.vars[name]; v != nil && !pythonReassigned(m, name) {
			return f.pyConstantPath(m, v, depth+1)
		}
		return false
	case "subscript":
		// app.config["X"]: Flask application configuration is not request data.
		if obj := n.ChildByFieldName("value"); obj != nil && obj.Kind() == "attribute" && pyText(m, obj.ChildByFieldName("attribute")) == "config" {
			if root := obj.ChildByFieldName("object"); root != nil && root.Kind() == "identifier" {
				if v := m.vars[pyText(m, root)]; v != nil && v.Kind() == "call" && f.set.qualified(m, pyText(m, v.ChildByFieldName("function"))) == "flask.Flask" {
					return true
				}
			}
		}
		return false
	case "call":
		q := f.set.qualified(m, pyText(m, n.ChildByFieldName("function")))
		if !pyModeledPathCalls[q] && !pyPathObjectNames[q] {
			return false
		}
		for _, a := range pyArgs(n) {
			if !f.pyConstantPath(m, a, depth+1) {
				return false
			}
		}
		return true
	}
	return false
}

// pyAlwaysExits reports a block that cannot fall through: a return, a raise, an
// abort call or an if/else whose every branch exits.
func (f *pythonFlow) pyAlwaysExits(n *sitter.Node) bool {
	if n == nil {
		return false
	}
	m := f.module
	switch n.Kind() {
	case "return_statement", "raise_statement":
		return true
	case "expression_statement":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			c := n.NamedChild(i)
			if c.Kind() == "call" {
				switch f.qualified(pyText(m, c.ChildByFieldName("function"))) {
				case "flask.abort", "werkzeug.exceptions.abort", "sys.exit", "fastapi.HTTPException":
					return true
				}
			}
		}
	case "block":
		for i := uint(0); i < n.NamedChildCount(); i++ {
			if f.pyAlwaysExits(n.NamedChild(i)) {
				return true
			}
		}
	case "if_statement":
		alt := n.ChildByFieldName("alternative")
		return alt != nil && f.pyAlwaysExits(n.ChildByFieldName("consequence")) && f.pyAlwaysExits(alt.ChildByFieldName("body"))
	}
	return false
}

// pythonPathGuards finds statements that dominate or enclose the call and
// mention a request-derived path value, and classifies each. Presence and type
// tests are not recorded.
func (f *pythonFlow) pythonPathGuards(call *sitter.Node, u *analysis.CandidateUse, operand map[string]bool, info *pathGuardInfo) []analysis.Evidence {
	m := f.module
	scope := call
	for p := call.Parent(); p != nil; p = p.Parent() {
		scope = p
		if p.Kind() == "function_definition" {
			break
		}
	}
	type depNames struct {
		idx   int
		names map[string]bool
		list  []string
	}
	var all []depNames
	defs := map[string]string{}
	for i, d := range u.Dependencies {
		if d.SinkSlot != analysis.PathSlotFile {
			continue
		}
		names := map[string]bool{}
		for name := range operand {
			names[name] = true
		}
		for _, name := range commandDepNames(d) {
			names[name] = true
		}
		f.deriveNames(scope, names, defs)
		list := make([]string, 0, len(names))
		for name := range names {
			list = append(list, name)
		}
		sort.Strings(list)
		all = append(all, depNames{i, names, list})
	}
	collection := func(name string) bool { return pyConstantCollection(m, name) }
	var guards []analysis.Evidence
	seen := map[int]bool{}
	consider := func(kind string, cond, whole *sitter.Node, guardEnd uint) {
		if cond == nil || seen[int(whole.StartByte())] {
			return
		}
		text := pyText(m, cond)
		covered := map[int]bool{}
		var union []string
		for _, d := range all {
			if !mentionsAny(text, d.list) || presenceOnlyCondition(text, d.list) {
				continue
			}
			var mentioned []string
			for _, name := range d.list {
				if mentionsAny(text, []string{name}) {
					mentioned = append(mentioned, name)
				}
			}
			if f.assignedBetween(scope, guardEnd, call.StartByte(), mentioned) {
				continue
			}
			covered[d.idx] = true
			union = append(union, d.list...)
		}
		if len(covered) == 0 {
			return
		}
		seen[int(whole.StartByte())] = true
		class := classifyPathGuardText(text, union, defs, collection)
		if class == analysis.PathGuardPresenceOrType {
			return // a presence or emptiness test never constrains content
		}
		ev := m.evidence(kind, whole)
		info.note(ev, class, covered)
		guards = append(guards, ev)
	}
	climb := func(start *sitter.Node) *sitter.Node {
		child := start
		for p := start.Parent(); p != nil; p = p.Parent() {
			switch p.Kind() {
			case "block", "module":
				for i := uint(0); i < p.NamedChildCount(); i++ {
					sib := p.NamedChild(i)
					if sib.StartByte() >= child.StartByte() {
						break
					}
					if sib.Kind() == "if_statement" && f.pyAlwaysExits(sib.ChildByFieldName("consequence")) {
						consider("terminating_guard", sib.ChildByFieldName("condition"), sib, sib.EndByte())
					}
				}
			case "if_statement":
				cond, consequence := p.ChildByFieldName("condition"), p.ChildByFieldName("consequence")
				if cond != nil && consequence != nil && child.StartByte() >= consequence.StartByte() && child.EndByte() <= consequence.EndByte() {
					consider("enclosing_guard", cond, cond, cond.EndByte())
				}
			}
			child = p
			if p.Kind() == "function_definition" {
				return p
			}
		}
		return nil
	}
	helper := climb(call)
	if helper != nil && f.route.fn != nil && helper.StartByte() != f.route.fn.StartByte() && f.route.module == m {
		// The sink is inside a helper: controls dominating its call site in the route
		// function apply to the values passed in. A call site without a control, among
		// several, leaves the flow unresolved.
		if id := helper.ChildByFieldName("name"); id != nil {
			name := pyText(m, id)
			var sites []*sitter.Node
			pyWalk(f.route.fn, func(n *sitter.Node) {
				if n.Kind() != "call" {
					return
				}
				if fn := n.ChildByFieldName("function"); fn != nil && fn.Kind() == "identifier" && pyText(m, fn) == name {
					sites = append(sites, n)
				}
			})
			for _, site := range sites {
				before := len(guards)
				climb(site)
				if len(guards) == before && len(sites) > 1 {
					info.ambiguousCallers = true
				}
			}
		}
	}
	return guards
}

// deriveNames extends names with variables assigned from a known name.
func (f *pythonFlow) deriveNames(scope *sitter.Node, names map[string]bool, defs map[string]string) {
	m := f.module
	for round := 0; round < 4; round++ {
		changed := false
		pyWalk(scope, func(n *sitter.Node) {
			if n.Kind() != "assignment" {
				return
			}
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left == nil || right == nil || left.Kind() != "identifier" {
				return
			}
			name := pyText(m, left)
			list := make([]string, 0, len(names))
			for known := range names {
				list = append(list, known)
			}
			if !names[name] && mentionsAny(pyText(m, right), list) {
				names[name] = true
				defs[name] = pyText(m, right)
				changed = true
			}
		})
		if !changed {
			return
		}
	}
}

// assignedBetween reports an assignment to one of the mentioned names between a
// control and the call, which makes the control inspect a different value.
func (f *pythonFlow) assignedBetween(scope *sitter.Node, from, to uint, mentioned []string) bool {
	found := false
	pyWalk(scope, func(n *sitter.Node) {
		if found || n.Kind() != "assignment" && n.Kind() != "augmented_assignment" || n.StartByte() < from || n.EndByte() > to {
			return
		}
		if left := n.ChildByFieldName("left"); left != nil && left.Kind() == "identifier" {
			for _, name := range mentioned {
				if pyText(f.module, left) == name {
					found = true
				}
			}
		}
	})
	return found
}

// pythonPathBlockerKind reports whether a gap kind can leave an operand path unresolved.
func pythonPathBlockerKind(kind string) bool {
	return pythonCommandBlockers[kind] || kind == "path_spread_unresolved"
}

// completePythonPath assembles the claim-scoped completeness for a Python use at
// the point where its flow, guards and operands are known.
func (f *pythonFlow) completePythonPath(u *analysis.CandidateUse, call *sitter.Node, operands pythonValue, guards []analysis.Evidence, guardIndex []int, names map[string]bool, info *pathGuardInfo) {
	m := f.module
	blockers := []analysis.Gap{}
	coverage := []analysis.Gap{}
	transfers := []analysis.Evidence{}
	for _, g := range append(append([]analysis.Gap{}, u.Gaps...), f.guardGaps(operands)...) {
		if !pythonPathBlockerKind(g.Kind) || (g.Kind == "python_call_unresolved" && g.At.StartByte == int(call.StartByte()) && g.At.File == m.file) {
			coverage = append(coverage, g)
			continue
		}
		if (g.Kind == "python_call_unresolved" || g.Kind == "python_value_unresolved" || g.Kind == "python_dispatch_unresolved") && !touchesCommandDependency(g, u.Dependencies) {
			coverage = append(coverage, g)
			continue
		}
		if evidence, ok := f.modeledPathGap(g); ok {
			coverage = append(coverage, g)
			if evidence.Kind != "" {
				transfers = append(transfers, evidence)
			}
			continue
		}
		if evidence, ok := f.supportedCommandGap(g, names); ok {
			coverage = append(coverage, g)
			transfers = append(transfers, evidence)
			continue
		}
		blockers = append(blockers, g)
	}
	extra := map[string][]analysis.Evidence{
		"invoked_callable": {f.route.module.evidence("invoked_callable", f.route.fn)},
		"control_flow":     append([]analysis.Evidence{m.evidence("operation", call)}, f.context...),
		"transformation":   transfers,
	}
	c := pathCompleteness(u, extra, dedupeGaps(blockers), dedupeGaps(coverage))
	for _, t := range transfers {
		c.ModelFacts = append(c.ModelFacts, "Supported transfer "+t.Kind+" "+t.Text+" at "+t.Span.File+" carries its operand into the result without a modeled constraint; it is not a validator.")
	}
	finishPathFlows(u, c, guards, guardIndex, info, func(g analysis.Gap, d analysis.Dependency) bool {
		return gapTouchesDependency(g, d) || pythonGapTouches(g, d)
	})
	u.Completeness = c
	u.Gaps = dedupeGaps(append(append([]analysis.Gap{}, u.Gaps...), blockers...))
}

// modeledPathGap recognizes a gap on a verified path call, a pathlib object or
// a constant trusted base. The returned evidence is empty for a constant base.
func (f *pythonFlow) modeledPathGap(g analysis.Gap) (analysis.Evidence, bool) {
	m := f.set.modules[g.At.File]
	if m == nil {
		return analysis.Evidence{}, false
	}
	node := nodeAt(m.tree.RootNode(), g.At.StartByte, g.At.EndByte)
	if node == nil {
		return analysis.Evidence{}, false
	}
	if f.pyConstantPath(m, node, 0) {
		return analysis.Evidence{}, true
	}
	if node.Kind() == "identifier" {
		// The Flask application object itself is not a value dependency.
		if v := m.vars[pyText(m, node)]; v != nil && v.Kind() == "call" && f.set.qualified(m, pyText(m, v.ChildByFieldName("function"))) == "flask.Flask" {
			return analysis.Evidence{}, true
		}
	}
	if node.Kind() == "identifier" || node.Kind() == "attribute" {
		// A reference to the os/io/pathlib module itself is not a value dependency.
		switch f.set.qualified(m, pyText(m, node)) {
		case "os", "os.path", "posixpath", "pathlib", "io", "urllib.parse":
			return analysis.Evidence{}, true
		}
	}
	if node.Kind() != "call" {
		return analysis.Evidence{}, false
	}
	fn := node.ChildByFieldName("function")
	q := f.set.qualified(m, pyText(m, fn))
	if pyModeledPathCalls[q] || pyPathObjectNames[q] {
		if f.set.commandTampered(m, strings.Split(q, ".")[0]) {
			return analysis.Evidence{}, false
		}
		return m.evidence("transformation", node), true
	}
	if fn != nil && fn.Kind() == "attribute" && pyPathMethods[pyText(m, fn.ChildByFieldName("attribute"))] {
		return m.evidence("transformation", node), true
	}
	return analysis.Evidence{}, false
}
