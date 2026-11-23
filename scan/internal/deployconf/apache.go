package deployconf

import "strings"

// apacheOptions are the Options names, in their documented spelling.
var apacheOptions = []string{"All", "ExecCGI", "FollowSymLinks", "Includes", "IncludesNOEXEC", "Indexes", "MultiViews", "None", "SymLinksIfOwnerMatch"}

// apacheAll is what Options All turns on: everything except MultiViews.
var apacheAll = []string{"ExecCGI", "FollowSymLinks", "Includes", "Indexes", "SymLinksIfOwnerMatch"}

type apacheFrame struct {
	tag, scope string
	line       int
	options    []string
	// skip marks a container whose scope is not a directory (Location,
	// Files, a pattern). Options inside it are not recorded.
	skip bool
}

// Apache reads Options, DocumentRoot, RemoteIPHeader and RemoteIPTrustedProxy.
// An .htaccess file scopes its directives to its own directory, as a project
// path.
func Apache(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	root := apacheFrame{}
	if strings.HasSuffix(file, ".htaccess") {
		root.scope, root.line = ".", 1
		if i := strings.LastIndex(file, "/"); i > 0 {
			root.scope = file[:i]
		}
	}
	stack := []apacheFrame{root}
	var out []Directive
	for _, row := range continuedLines(src) {
		text := strings.TrimSpace(stripComment(row.text, "#"))
		if text == "" {
			continue
		}
		top := &stack[len(stack)-1]
		if strings.HasPrefix(text, "</") {
			if tag := apacheTag(text[2:]); len(stack) > 1 && top.tag == tag {
				stack = stack[:len(stack)-1]
			}
			continue
		}
		if strings.HasPrefix(text, "<") {
			tag := apacheTag(text[1:])
			next := apacheFrame{tag: tag, scope: top.scope, line: top.line, options: append([]string{}, top.options...), skip: top.skip}
			switch tag {
			case "directory":
				next.scope, next.line = apacheArgument(text), row.num
			case "virtualhost":
			case "ifmodule", "ifdefine", "ifversion":
				// A conditional container does not change the scope.
				continue
			default:
				next.skip = true
			}
			stack = append(stack, next)
			continue
		}
		toks := fieldsQuoted(text)
		switch strings.ToLower(toks[0]) {
		case "options":
			if top.skip {
				continue
			}
			top.options = applyOptions(top.options, unquoteAll(toks[1:]))
			out = append(out, Directive{
				File: file, Line: row.num, Name: "Options", Values: unquoteAll(toks[1:]),
				Scope: top.scope, ScopeLine: top.line, Effective: append([]string{}, top.options...),
			})
		case "documentroot", "remoteipheader", "remoteiptrustedproxy":
			val := ""
			if len(toks) > 1 {
				val = unquote(toks[1])
			}
			out = append(out, Directive{File: file, Line: row.num, Name: canonicalApache(toks[0]), Values: []string{val}, Scope: top.scope, ScopeLine: top.line})
		}
	}
	return out, nil
}

func apacheTag(rest string) string {
	end := strings.IndexAny(rest, " \t>")
	if end < 0 {
		end = len(rest)
	}
	return strings.ToLower(rest[:end])
}

func apacheArgument(text string) string {
	i := strings.IndexAny(text, " \t")
	j := strings.LastIndexByte(text, '>')
	if i < 0 || j < i {
		return ""
	}
	return unquote(strings.TrimSpace(text[i:j]))
}

func canonicalApache(name string) string {
	switch strings.ToLower(name) {
	case "documentroot":
		return "DocumentRoot"
	case "remoteipheader":
		return "RemoteIPHeader"
	case "remoteiptrustedproxy":
		return "RemoteIPTrustedProxy"
	}
	return name
}

// canonicalOption returns the documented spelling of an option name.
// Apache compares the names without regard to case.
func canonicalOption(name string) string {
	for _, known := range apacheOptions {
		if strings.EqualFold(name, known) {
			return known
		}
	}
	return name
}

// applyOptions implements Apache's relative and replacement forms.
// A list whose every token has + or - edits the list in force. Any bare
// token replaces it. None clears the list and All adds every option except
// MultiViews.
func applyOptions(current, tokens []string) []string {
	relative := len(tokens) > 0
	for _, t := range tokens {
		if t == "" || (t[0] != '+' && t[0] != '-') {
			relative = false
		}
	}
	var list []string
	if relative {
		list = append(list, current...)
	}
	add := func(name string) {
		for _, have := range list {
			if have == name {
				return
			}
		}
		list = append(list, name)
	}
	for _, t := range tokens {
		remove := strings.HasPrefix(t, "-")
		names := []string{canonicalOption(strings.TrimLeft(t, "+-"))}
		switch names[0] {
		case "None":
			if !remove {
				list = nil
			}
			continue
		case "All":
			names = apacheAll
		}
		for _, name := range names {
			if !remove {
				add(name)
				continue
			}
			kept := list[:0:0]
			for _, have := range list {
				if have != name {
					kept = append(kept, have)
				}
			}
			list = kept
		}
	}
	return list
}

// Indexes reports whether an Options effective list enables listing.
func Indexes(effective []string) bool {
	for _, name := range effective {
		if name == "Indexes" {
			return true
		}
	}
	return false
}
