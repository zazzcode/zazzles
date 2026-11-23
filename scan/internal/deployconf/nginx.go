package deployconf

import (
	"path"
	"strings"
)

type nginxBlock struct {
	parent   *nginxBlock
	header   string
	line     int
	root     string
	alias    bool
	children []*nginxStatement
}

type nginxStatement struct {
	text  string
	line  int
	block *nginxBlock
}

// Nginx reads autoindex, root, real_ip_header and set_real_ip_from with the
// enclosing location, if any. Statements end at ';' and blocks nest by
// braces, so one line may hold several statements.
func Nginx(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	top := &nginxBlock{}
	cur := top
	var b strings.Builder
	start := 0
	flush := func() string {
		text := strings.TrimSpace(b.String())
		b.Reset()
		return text
	}
	for _, row := range physicalLines(src) {
		text := stripComment(row.text, "#")
		quote := byte(0)
		for i := 0; i < len(text); i++ {
			c := text[i]
			if b.Len() == 0 && quote == 0 && (c == ' ' || c == '\t') {
				continue
			}
			if b.Len() == 0 {
				start = row.num
			}
			switch {
			case quote != 0:
				b.WriteByte(c)
				if c == quote {
					quote = 0
				}
			case c == '"' || c == '\'':
				quote = c
				b.WriteByte(c)
			case c == ';':
				cur.children = append(cur.children, &nginxStatement{text: flush(), line: start})
			case c == '{':
				next := &nginxBlock{parent: cur, header: flush(), line: start}
				cur.children = append(cur.children, &nginxStatement{line: start, block: next})
				cur = next
			case c == '}':
				flush()
				if cur.parent != nil {
					cur = cur.parent
				}
			default:
				b.WriteByte(c)
			}
		}
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
	}
	var out []Directive
	nginxEmit(file, top, &out)
	return out, nil
}

// nginxEmit resolves each block's root before its statements, because nginx
// applies a root wherever it is written in the block.
func nginxEmit(file string, blk *nginxBlock, out *[]Directive) {
	if blk.parent != nil {
		blk.root = blk.parent.root
	}
	for _, st := range blk.children {
		if st.block != nil {
			continue
		}
		toks := unquoteAll(fieldsQuoted(st.text))
		if len(toks) > 1 && toks[0] == "root" {
			blk.root = toks[1]
		}
		if len(toks) > 1 && toks[0] == "alias" {
			blk.alias = true
		}
	}
	scope, scopeLine, dir := nginxScope(blk)
	for _, st := range blk.children {
		if st.block != nil {
			nginxEmit(file, st.block, out)
			continue
		}
		toks := unquoteAll(fieldsQuoted(st.text))
		if len(toks) == 0 {
			continue
		}
		switch name := strings.ToLower(toks[0]); name {
		case "autoindex", "root", "real_ip_header", "set_real_ip_from":
			val := ""
			if len(toks) > 1 {
				val = toks[1]
			}
			*out = append(*out, Directive{File: file, Line: st.line, Name: name, Values: []string{val}, Scope: scope, ScopeLine: scopeLine, Dir: dir})
		}
	}
}

// nginxScope names the innermost location of a block and the directory it
// serves. A pattern location or an alias has no directory.
func nginxScope(blk *nginxBlock) (scope string, line int, dir string) {
	dir = blk.root
	for b := blk; b != nil; b = b.parent {
		toks := fieldsQuoted(b.header)
		if len(toks) == 0 || toks[0] != "location" {
			continue
		}
		scope, line = strings.Join(toks, " "), b.line
		args := unquoteAll(toks[1:])
		if len(args) == 2 && (args[0] == "=" || args[0] == "^~") {
			args = args[1:]
		}
		if len(args) != 1 || b.alias || blk.root == "" || !strings.HasPrefix(args[0], "/") {
			return scope, line, ""
		}
		return scope, line, path.Join(blk.root, args[0])
	}
	return "", 0, dir
}
