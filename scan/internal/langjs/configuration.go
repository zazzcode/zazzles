package langjs

import (
	"fmt"
	"os"
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
	dir, ok := stringLiteral(arg, m.src)
	if !ok || dir == "" || filepath.IsAbs(dir) {
		return analysis.Evidence{}, false
	}
	clean := filepath.Clean(filepath.FromSlash(dir))
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
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
