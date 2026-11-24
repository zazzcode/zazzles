package langjs

import (
	"path"
	"strings"

	sitter "github.com/tree-sitter/go-tree-sitter"
)

// servedDirectory is a directory operand resolved to a comparable form. base
// says what the path is relative to: "cwd" for the process working directory
// (a relative string, path.resolve), "root" for the scan root (a path built
// from __dirname) and "abs" for an absolute path. Two directories compare
// only within one base: where the process starts is not in the source.
type servedDirectory struct{ base, path string }

func (d servedDirectory) covers(other servedDirectory) bool {
	if d.base == "" || d.base != other.base || strings.HasPrefix(other.path, "..") {
		return false
	}
	return d.path == other.path || d.path == "." || d.path == "/" || strings.HasPrefix(other.path, d.path+"/")
}

// servedBy is yes when a file-serving middleware's directory covers d, no
// when every such directory in the project is comparable with d and none
// covers it, and unknown otherwise.
func (d servedDirectory) servedBy(mounts []servedDirectory) string {
	comparable := true
	for _, mount := range mounts {
		if mount.covers(d) {
			return "yes"
		}
		comparable = comparable && mount.base == d.base
	}
	if comparable {
		return "no"
	}
	return "unknown"
}

// servedDirectories returns the directory of every express.static and
// serve-index call in the selected modules. Both serve the files under the
// directory they are given (https://expressjs.com/en/4x/api.html#express.static,
// https://github.com/expressjs/serve-index#readme). A directory that does not
// resolve is kept as the zero value, which compares with nothing.
func (s *moduleSet) servedDirectories(selected []string) []servedDirectory {
	var out []servedDirectory
	for _, file := range selected {
		m := s.modules[file]
		if m == nil || m.tree.RootNode().HasError() {
			continue
		}
		walkCalls(m.tree.RootNode(), func(call *sitter.Node) {
			if !libraryCall(m, call, "express", "static") && !libraryCall(m, call, "serve-index", "") {
				return
			}
			dir, _ := resolveDirectory(m, jsArgument(call.ChildByFieldName("arguments"), 0), 0)
			out = append(out, dir)
		})
	}
	return out
}

// resolveDirectory resolves a directory operand: a string literal, a module
// constant bound to one, or path.resolve/path.join over string literals,
// optionally starting at __dirname.
func resolveDirectory(m *sourceModule, n *sitter.Node, depth int) (servedDirectory, bool) {
	n = unwrapTS(n)
	if n == nil {
		return servedDirectory{}, false
	}
	switch n.Kind() {
	case "string":
		text, ok := stringLiteral(n, m.src)
		if !ok || text == "" {
			return servedDirectory{}, false
		}
		if strings.HasPrefix(text, "/") {
			return servedDirectory{"abs", path.Clean(text)}, true
		}
		return servedDirectory{"cwd", path.Clean(text)}, true
	case "identifier":
		name := n.Utf8Text(m.src)
		if depth > 0 || shadowed(n, name, m.src) || bindingReassigned(m, name) {
			return servedDirectory{}, false
		}
		return resolveDirectory(m, topVariable(m, name), depth+1)
	case "call_expression":
		resolve := pathCall(m, n, "resolve")
		if !resolve && !pathCall(m, n, "join") {
			return servedDirectory{}, false
		}
		args := n.ChildByFieldName("arguments")
		dir := servedDirectory{base: "cwd"}
		var parts []string
		for i := uint(0); i < args.NamedChildCount(); i++ {
			a := unwrapTS(args.NamedChild(i))
			if i == 0 && a.Kind() == "identifier" && a.Utf8Text(m.src) == "__dirname" && !moduleBinds(m, "__dirname") && !shadowed(n, "__dirname", m.src) {
				dir.base, parts = "root", []string{path.Dir(m.file)}
				continue
			}
			text, ok := stringLiteral(a, m.src)
			if !ok || text == "" {
				return servedDirectory{}, false
			}
			if strings.HasPrefix(text, "/") && (resolve || len(parts) == 0) {
				dir.base, parts = "abs", nil // an absolute segment restarts path.resolve
			}
			parts = append(parts, text)
		}
		if len(parts) == 0 {
			return servedDirectory{}, false
		}
		dir.path = path.Clean(path.Join(parts...))
		return dir, true
	}
	return servedDirectory{}, false
}
