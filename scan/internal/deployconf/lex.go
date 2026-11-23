package deployconf

import (
	"strings"
	"unicode"
)

// line is one logical line. starts maps a byte offset in text to the
// physical line it came from, in ascending offset order.
type line struct {
	text   string
	num    int
	starts []lineStart
}

type lineStart struct{ off, num int }

// at returns the physical line of a byte offset in the logical text.
func (l line) at(off int) int {
	num := l.num
	for _, s := range l.starts {
		if s.off > off {
			break
		}
		num = s.num
	}
	return num
}

// physicalLines returns each line of src with its number.
func physicalLines(src []byte) []line {
	raw := strings.Split(string(src), "\n")
	out := make([]line, 0, len(raw))
	for i, text := range raw {
		out = append(out, line{text: strings.TrimSuffix(text, "\r"), num: i + 1})
	}
	return out
}

// continuedLines joins a line that ends in a backslash to the next one, as
// Apache and Dockerfile syntax do. A whole-line comment inside a
// continuation is dropped, as Docker drops it.
func continuedLines(src []byte) []line {
	raw := physicalLines(src)
	var out []line
	for i := 0; i < len(raw); i++ {
		cur := line{num: raw[i].num}
		var b strings.Builder
		started := false
		for {
			piece := raw[i].text
			if started && strings.HasPrefix(strings.TrimSpace(piece), "#") {
				if i+1 >= len(raw) {
					break
				}
				i++
				continue
			}
			started = true
			cont := strings.HasSuffix(piece, "\\")
			cur.starts = append(cur.starts, lineStart{b.Len(), raw[i].num})
			b.WriteString(strings.TrimSuffix(piece, "\\"))
			if !cont || i+1 >= len(raw) {
				break
			}
			b.WriteByte(' ')
			i++
		}
		cur.text = b.String()
		out = append(out, cur)
	}
	return out
}

// stripComment cuts text at the first unquoted comment mark. A '#' starts a
// comment only at the start of the text or after white space, so a URL
// fragment stays. Leading text is kept so byte offsets still hold.
func stripComment(text, marks string) string {
	quote := byte(0)
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case strings.IndexByte(marks, c) >= 0:
			if c != '#' || i == 0 || unicode.IsSpace(rune(text[i-1])) {
				return strings.TrimRight(text[:i], " \t")
			}
		}
	}
	return strings.TrimRight(text, " \t")
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// fieldsQuoted splits on white space outside quotes. Quotes are kept.
func fieldsQuoted(text string) []string {
	var out []string
	var b strings.Builder
	quote := byte(0)
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			b.WriteByte(c)
		case unicode.IsSpace(rune(c)):
			flush()
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return out
}

func unquoteAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = unquote(s)
	}
	return out
}

// segment is one shell command of a line and its byte offset in that line.
type segment struct {
	text string
	off  int
}

// shellSegments splits shell text on unquoted `&&`, `||` and `;`.
func shellSegments(text string) []segment {
	var out []segment
	quote := byte(0)
	start := 0
	cut := func(end, next int) {
		if strings.TrimSpace(text[start:end]) != "" {
			lead := len(text[start:end]) - len(strings.TrimLeft(text[start:end], " \t"))
			out = append(out, segment{text: strings.TrimSpace(text[start:end]), off: start + lead})
		}
		start = next
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == ';':
			cut(i, i+1)
		case (c == '&' || c == '|') && i+1 < len(text) && text[i+1] == c:
			cut(i, i+2)
			i++
		}
	}
	cut(len(text), len(text))
	return out
}
