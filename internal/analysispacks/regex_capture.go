package analysispacks

import (
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// Regular-expression flavors a capture group is read under.
const (
	FlavorECMAScript = "ecmascript"
	FlavorPCRE       = "pcre"
	FlavorPython     = "python"
)

// Capture-group classes (close-findings-gaps D-5). The class states what a
// captured value can hold, never whether that is adequate for an operation.
const (
	// CaptureAdmitsAny: the sub-pattern contains '.', \S, \W, \D, or a
	// negated class that excludes none of the shell command metacharacters.
	CaptureAdmitsAny = "admits_any"
	// CaptureExplicitAlphabet: only literals and positive classes; the
	// accepted characters are listed.
	CaptureExplicitAlphabet = "explicit_alphabet"
	// CaptureUnknown: backreferences, lookaround or unsupported syntax.
	CaptureUnknown = "unknown"
)

// shellMetacharacters start a new command, a substitution or a redirection
// on one POSIX shell line. A negated class that excludes none of them admits
// all of them.
const shellMetacharacters = ";|&$`()<>"

// CaptureClass is the classification of one capture group's sub-pattern.
type CaptureClass struct {
	Class    string `json:"class"`
	Alphabet string `json:"alphabet,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// CaptureSubPattern returns the source text of capturing group n (1-based)
// of pattern, without its parentheses or group name.
func CaptureSubPattern(pattern string, n int) (string, bool) {
	count, inClass := 0, false
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		switch {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(pattern) && pattern[i+1] == '^' {
				i++
			}
			if i+1 < len(pattern) && pattern[i+1] == ']' {
				i++
			}
		case c == '(':
			body, capturing := groupBody(pattern, i)
			if !capturing {
				continue
			}
			count++
			if count != n {
				continue
			}
			end := closingParen(pattern, i)
			if end < 0 {
				return "", false
			}
			return pattern[body:end], true
		}
	}
	return "", false
}

// groupBody returns where a group opened at i starts its body and whether
// the group captures.
func groupBody(p string, i int) (int, bool) {
	rest := p[i+1:]
	switch {
	case !strings.HasPrefix(rest, "?"):
		return i + 1, true
	case strings.HasPrefix(rest, "?P<"), strings.HasPrefix(rest, "?<") && !strings.HasPrefix(rest, "?<=") && !strings.HasPrefix(rest, "?<!"), strings.HasPrefix(rest, "?'"):
		closer := ">"
		if strings.HasPrefix(rest, "?'") {
			closer = "'"
		}
		start := strings.Index(rest, "<")
		if closer == "'" {
			start = 1
		}
		end := strings.Index(rest[start+1:], closer)
		if end < 0 {
			return i + 1, false
		}
		return i + 1 + start + 1 + end + 1, true
	}
	return i + 1, false
}

func closingParen(p string, open int) int {
	depth, inClass := 0, false
	for i := open; i < len(p); i++ {
		c := p[i]
		switch {
		case c == '\\':
			i++
		case inClass:
			if c == ']' {
				inClass = false
			}
		case c == '[':
			inClass = true
			if i+1 < len(p) && p[i+1] == '^' {
				i++
			}
			if i+1 < len(p) && p[i+1] == ']' {
				i++
			}
		case c == '(':
			depth++
		case c == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// classState accumulates what a sub-pattern can accept.
type classState struct {
	set             map[rune]bool
	unicode         []string
	admitsAny       bool
	unknown         string
	flavor, flags   string
	caseInsensitive bool
}

func (s *classState) fail(reason string) {
	if s.unknown == "" {
		s.unknown = reason
	}
}

func (s *classState) add(r rune) {
	s.set[r] = true
	if s.caseInsensitive {
		s.set[unicode.ToUpper(r)] = true
		s.set[unicode.ToLower(r)] = true
	}
}

func (s *classState) addRange(lo, hi rune) {
	for r := lo; r <= hi; r++ {
		s.add(r)
	}
}

// shorthand applies \d, \w or \s as a positive set.
func (s *classState) shorthand(c byte) {
	switch c {
	case 'd':
		s.addRange('0', '9')
		s.note("decimal digits")
	case 'w':
		s.addRange('0', '9')
		s.addRange('A', 'Z')
		s.addRange('a', 'z')
		s.add('_')
		s.note("word characters")
	case 's':
		for _, r := range " \t\n\v\f\r" {
			s.add(r)
		}
		s.note("whitespace")
	}
}

// note records that a Python str shorthand also matches non-ASCII characters
// unless the ASCII flag is set.
func (s *classState) note(what string) {
	if s.flavor == FlavorPython && !strings.Contains(s.flags, "a") {
		s.unicode = append(s.unicode, what)
	}
}

// ClassifyCapture classifies a capture group's sub-pattern under a flavor
// and the expression's flags (for example "i", "x", "s").
func ClassifyCapture(sub, flavor, flags string) CaptureClass {
	class, _ := classifyCapture(sub, flavor, flags)
	return class
}

// classifyCapture also returns the accepted characters of an
// explicit_alphabet class when the listing is complete; the set is nil for
// every other class and when unlisted Unicode characters are also accepted.
func classifyCapture(sub, flavor, flags string) (CaptureClass, map[rune]bool) {
	s := &classState{set: map[rune]bool{}, flavor: flavor, flags: flags, caseInsensitive: strings.Contains(flags, "i")}
	if strings.Contains(flags, "x") {
		return CaptureClass{Class: CaptureUnknown, Reason: "extended (verbose) syntax is not modelled"}, nil
	}
	for i := 0; i < len(sub); i++ {
		c := sub[i]
		switch c {
		case '\\':
			if i+1 >= len(sub) {
				s.fail("trailing backslash")
				break
			}
			i++
			i = s.escape(sub, i, false)
		case '.':
			s.admitsAny = true
		case '[':
			i = s.class(sub, i)
		case '(':
			rest := sub[i+1:]
			switch {
			case !strings.HasPrefix(rest, "?"), strings.HasPrefix(rest, "?:"):
			case strings.HasPrefix(rest, "?="), strings.HasPrefix(rest, "?!"), strings.HasPrefix(rest, "?<="), strings.HasPrefix(rest, "?<!"):
				s.fail("lookaround")
			case strings.HasPrefix(rest, "?P<"), strings.HasPrefix(rest, "?<"), strings.HasPrefix(rest, "?'"):
				body, _ := groupBody(sub, i)
				i = body - 1
			default:
				s.fail("unsupported group syntax")
			}
		case ')', '|', '^', '$', '*', '+', '?':
		case '{':
			end := strings.IndexByte(sub[i:], '}')
			if end > 0 && quantifierBody(sub[i+1:i+end]) {
				i += end
			} else {
				s.add('{')
			}
		default:
			r, size := decodeRune(sub[i:])
			s.add(r)
			i += size - 1
		}
	}
	switch {
	case s.unknown != "":
		return CaptureClass{Class: CaptureUnknown, Reason: s.unknown}, nil
	case s.admitsAny:
		return CaptureClass{Class: CaptureAdmitsAny, Reason: "the sub-pattern accepts any character, including shell syntax"}, nil
	}
	alphabet := formatAlphabet(s.set)
	if len(s.unicode) > 0 {
		// The listed characters are not the whole accepted set.
		alphabet += " and other Unicode " + strings.Join(s.unicode, ", ")
		return CaptureClass{Class: CaptureExplicitAlphabet, Alphabet: alphabet}, nil
	}
	return CaptureClass{Class: CaptureExplicitAlphabet, Alphabet: alphabet}, s.set
}

func quantifierBody(b string) bool {
	if b == "" {
		return false
	}
	for _, c := range b {
		if c != ',' && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func decodeRune(s string) (rune, int) {
	for i, r := range s {
		if i == 0 {
			return r, len(string(r))
		}
	}
	return 0, 1
}

// escape handles the escape whose letter is at sub[i] and returns the index
// of its last byte. inClass changes only \b (backspace in a class).
func (s *classState) escape(sub string, i int, inClass bool) int {
	c := sub[i]
	switch {
	case c == 'd' || c == 'w' || c == 's':
		s.shorthand(c)
	case c == 'D' || c == 'W' || c == 'S':
		s.admitsAny = true
	case !inClass && (c == 'b' || c == 'B' || c == 'A' || c == 'z' || c == 'Z'):
	case c >= '1' && c <= '9', c == 'k', c == 'g' && s.flavor == FlavorPCRE:
		s.fail("backreference")
	case c == 'n':
		s.add('\n')
	case c == 't':
		s.add('\t')
	case c == 'r':
		s.add('\r')
	case c == 'f':
		s.add('\f')
	case c == 'v':
		s.add('\v')
	case c == '0':
		s.add(0)
	case c == 'x' && i+2 < len(sub):
		v, err := strconv.ParseUint(sub[i+1:i+3], 16, 32)
		if err != nil {
			s.fail("unsupported hexadecimal escape")
			return i
		}
		s.add(rune(v))
		return i + 2
	case c == 'u' && i+4 < len(sub):
		v, err := strconv.ParseUint(sub[i+1:i+5], 16, 32)
		if err != nil {
			s.fail("unsupported unicode escape")
			return i
		}
		s.add(rune(v))
		return i + 4
	case c < 0x80 && (unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c))):
		s.fail("unsupported escape \\" + string(c))
	default:
		r, size := decodeRune(sub[i:])
		s.add(r)
		return i + size - 1
	}
	return i
}

// class reads a bracket expression opened at sub[i] and returns the index of
// its closing bracket.
func (s *classState) class(sub string, i int) int {
	inner := &classState{set: map[rune]bool{}, flavor: s.flavor, flags: s.flags, caseInsensitive: s.caseInsensitive}
	j := i + 1
	negated := j < len(sub) && sub[j] == '^'
	if negated {
		j++
	}
	first := true
	var prev rune = -1
	for ; j < len(sub); j++ {
		c := sub[j]
		if c == ']' && !first {
			break
		}
		first = false
		switch {
		case c == '[' && j+1 < len(sub) && sub[j+1] == ':':
			inner.fail("POSIX class")
			prev = -1
		case c == '\\' && j+1 < len(sub):
			j++
			before := len(inner.set)
			j = inner.escape(sub, j, true)
			prev = -1
			if len(inner.set) == before+1 {
				for r := range inner.set {
					prev = r // a single escaped literal can start a range
				}
			}
		case c == '-' && prev >= 0 && j+1 < len(sub) && sub[j+1] != ']':
			hi, size := decodeRune(sub[j+1:])
			if sub[j+1] == '\\' {
				inner.fail("escaped range end")
			} else if hi < prev {
				inner.fail("reversed range")
			} else {
				inner.addRange(prev, hi)
			}
			j += size
			prev = -1
		default:
			r, size := decodeRune(sub[j:])
			inner.add(r)
			prev = r
			j += size - 1
		}
	}
	if j >= len(sub) {
		s.fail("unterminated class")
		return len(sub) - 1
	}
	switch {
	case inner.unknown != "":
		s.fail(inner.unknown)
	case negated && inner.admitsAny:
		s.fail("negated class of a negated shorthand")
	case negated:
		for _, m := range shellMetacharacters {
			if inner.set[m] {
				s.fail("negated class excludes a shell metacharacter; its accepted set is not listed")
				return j
			}
		}
		s.admitsAny = true
	case inner.admitsAny:
		s.admitsAny = true
	default:
		for r := range inner.set {
			s.set[r] = true
		}
		s.unicode = append(s.unicode, inner.unicode...)
	}
	return j
}

// formatAlphabet lists runes in code-point order; runs of three or more are
// written as ranges.
func formatAlphabet(set map[rune]bool) string {
	runes := make([]rune, 0, len(set))
	for r := range set {
		runes = append(runes, r)
	}
	sort.Slice(runes, func(i, j int) bool { return runes[i] < runes[j] })
	var b strings.Builder
	for i := 0; i < len(runes); {
		j := i
		for j+1 < len(runes) && runes[j+1] == runes[j]+1 {
			j++
		}
		if j-i >= 2 {
			b.WriteString(showRune(runes[i]) + "-" + showRune(runes[j]))
			i = j + 1
			continue
		}
		b.WriteString(showRune(runes[i]))
		i++
	}
	return b.String()
}

func showRune(r rune) string {
	switch r {
	case ' ':
		return "[space]"
	case '\t':
		return `[\t]`
	case '\n':
		return `[\n]`
	case '\v':
		return `[\v]`
	case '\f':
		return `[\f]`
	case '\r':
		return `[\r]`
	}
	if r < 0x20 || r == 0x7f {
		return "[\\x" + strconv.FormatInt(int64(r), 16) + "]"
	}
	return string(r)
}

// PHPRegexLiteral reads a PHP string literal holding a PCRE pattern with its
// delimiters and modifiers.
func PHPRegexLiteral(literal string) (pattern, flags string, ok bool) {
	literal = strings.TrimSpace(literal)
	if len(literal) < 2 {
		return "", "", false
	}
	q := literal[0]
	if (q != '\'' && q != '"') || literal[len(literal)-1] != q {
		return "", "", false
	}
	body := literal[1 : len(literal)-1]
	if q == '\'' {
		body = strings.NewReplacer(`\\`, `\`, `\'`, `'`).Replace(body)
	} else {
		for i := 0; i+1 < len(body); i++ {
			if body[i] == '$' && (i == 0 || body[i-1] != '\\') && (body[i+1] == '_' || body[i+1] == '{' || unicode.IsLetter(rune(body[i+1]))) {
				return "", "", false // an interpolated variable
			}
		}
		body = strings.NewReplacer(`\\`, `\`, `\"`, `"`, `\$`, `$`).Replace(body)
	}
	body = strings.TrimLeft(body, " \t\n")
	if body == "" {
		return "", "", false
	}
	open := rune(body[0])
	if unicode.IsLetter(open) || unicode.IsDigit(open) || open == '\\' {
		return "", "", false
	}
	closer := map[rune]byte{'(': ')', '[': ']', '{': '}', '<': '>'}[open]
	if closer == 0 {
		closer = byte(open)
	}
	end := strings.LastIndexByte(body, closer)
	if end <= 0 {
		return "", "", false
	}
	return body[1:end], body[end+1:], true
}

// JSRegexLiteral reads an ECMAScript regular-expression literal.
func JSRegexLiteral(literal string) (pattern, flags string, ok bool) {
	literal = strings.TrimSpace(literal)
	if len(literal) < 2 || literal[0] != '/' {
		return "", "", false
	}
	end := strings.LastIndexByte(literal, '/')
	if end <= 0 {
		return "", "", false
	}
	for _, c := range literal[end+1:] {
		if !strings.ContainsRune("dgimsuvy", c) {
			return "", "", false
		}
	}
	return literal[1:end], literal[end+1:], true
}

// PythonStringLiteral reads a single-line Python string literal used as a
// pattern: raw literals keep backslashes; other literals keep the escapes
// the re module itself reads.
func PythonStringLiteral(literal string) (string, bool) {
	literal = strings.TrimSpace(literal)
	raw := false
	for len(literal) > 0 && strings.ContainsRune("rRbBuU", rune(literal[0])) {
		raw = raw || literal[0] == 'r' || literal[0] == 'R'
		literal = literal[1:]
	}
	if len(literal) < 2 {
		return "", false
	}
	q := literal[0]
	if (q != '\'' && q != '"') || literal[len(literal)-1] != q || strings.HasPrefix(literal, `"""`) || strings.HasPrefix(literal, `'''`) {
		return "", false
	}
	body := literal[1 : len(literal)-1]
	if !raw {
		body = strings.NewReplacer(`\\`, `\`, `\'`, `'`, `\"`, `"`).Replace(body)
	}
	return body, true
}
