package main

import (
	"bytes"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"
)

var (
	commentMarker  = regexp.MustCompile(`<!--|-->`)
	conflictMarker = regexp.MustCompile(`^(?:<{7}|\|{7}|>{7})(?:[ \t]|$)`)
	promptRules    = []struct {
		pattern *regexp.Regexp
		message string
	}{
		{regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override)\s+(?:(?:all|the|any|your)\s+)*(?:previous|prior|above|earlier|system|developer)\s+(?:instructions?|rules?|messages?|prompts?)\b`), "possible prompt injection (instruction override)"},
		{regexp.MustCompile(`(?i)\b(?:reveal|show|print|return|repeat|dump|disclose)\s+(?:(?:the|your|original|full)\s+)*(?:system|developer)\s+(?:prompt|message|instructions?)\b`), "possible prompt injection (prompt disclosure)"},
		{regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:(?:an?|in)\s+)?(?:system|administrator|admin|developer|unrestricted|developer mode)\b|\[/?INST\]|<\|(?:imstart|imend|system|assistant|user|startheaderid|endheaderid)\|>`), "possible prompt injection (role control)"},
		{regexp.MustCompile(`(?i)\bexfiltrate\s+(?:(?:the|all|any)\s+)*(?:secrets?|credentials?|tokens?|keys?|data)\b`), "possible prompt injection (data exfiltration)"},
		{regexp.MustCompile(`(?i)\b(?:curl|wget)\s+[^|\n]*\|\s*(?:(?:sudo|env)\s+)*(?:[\w./-]+/)?(?:ba|da|z|k)?sh\b`), "remote download piped into a shell"},
	}
)

type sourceLine struct {
	raw        []byte
	decoded    string
	promptText string
	hasNewline bool
	changed    bool
}

// A nil span list means the entire file was added. Unchanged lines supply
// comment and paragraph context without generating findings on their own.
func lintLines(blob []byte, spans []lineSpan, report func(int, string)) {
	lines := readLines(blob, spans)
	prompts := promptFindings(lines)
	inComment := false
	for i, line := range lines {
		commented := inComment
		for _, marker := range commentMarker.FindAll(line.raw, -1) {
			inComment = marker[0] == '<'
			commented = commented || inComment
		}
		if !line.changed {
			continue
		}
		lintLine(line, i+1, commented, report)
		for _, message := range prompts[i] {
			report(i+1, message)
		}
	}
}

func readLines(blob []byte, spans []lineSpan) []sourceLine {
	allLines := spans == nil
	var lines []sourceLine
	for raw := range bytes.Lines(blob) {
		number := len(lines) + 1
		for len(spans) > 0 && spans[0].end <= number {
			spans = spans[1:]
		}
		changed := allLines || len(spans) > 0 && spans[0].first <= number
		text, hasNewline := bytes.CutSuffix(raw, []byte("\n"))
		if hasNewline {
			text = bytes.TrimSuffix(text, []byte("\r"))
		}
		decoded := html.UnescapeString(string(text))
		lines = append(lines, sourceLine{
			raw: text, decoded: decoded, promptText: normalizePrompt(decoded),
			hasNewline: hasNewline, changed: changed,
		})
	}
	return lines
}

func normalizePrompt(text string) string {
	normalized := strings.Map(func(r rune) rune {
		// The fullwidth forms of printable ASCII have the same textual role.
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		switch {
		case unicode.IsSpace(r):
			return ' '
		case hiddenRune(r), r == '*', r == '_', r == '`':
			return -1
		default:
			return r
		}
	}, text)

	// A wrapped directive can repeat the blockquote prefix on every line.
	normalized = strings.TrimLeft(normalized, " ")
	for strings.HasPrefix(normalized, ">") {
		normalized = strings.TrimLeft(normalized[1:], " ")
	}
	return normalized
}

func promptFindings(lines []sourceLine) map[int][]string {
	findings := make(map[int][]string)
	start := 0
	for end := 0; end < len(lines); end++ {
		if strings.TrimSpace(lines[end].promptText) == "" {
			lintParagraph(lines[start:end], start, findings)
			start = end + 1
		}
	}
	lintParagraph(lines[start:], start, findings)
	return findings
}

func lintParagraph(lines []sourceLine, start int, findings map[int][]string) {
	if !slices.ContainsFunc(lines, func(line sourceLine) bool { return line.changed }) {
		return
	}
	var text strings.Builder
	var ends []int
	for _, line := range lines {
		text.WriteString(line.promptText)
		text.WriteByte('\n')
		ends = append(ends, text.Len())
	}
	for _, rule := range promptRules {
		lastReported := -1
		for _, match := range rule.pattern.FindAllStringIndex(text.String(), -1) {
			first, _ := slices.BinarySearch(ends, match[0]+1)
			last, _ := slices.BinarySearch(ends, match[1])
			for i := first; i <= last; i++ {
				if lines[i].changed {
					if i != lastReported {
						findings[start+i] = append(findings[start+i], rule.message)
						lastReported = i
					}
					break
				}
			}
		}
	}
}

func lintLine(line sourceLine, number int, commented bool, report func(int, string)) {
	if !utf8.Valid(line.raw) || bytes.IndexByte(line.raw, 0) >= 0 {
		report(number, "expected UTF-8 text without NUL bytes")
	}
	var hidden map[rune]bool
	for _, r := range line.decoded {
		if r != 0 && hiddenRune(r) && !hidden[r] {
			report(number, fmt.Sprintf("hidden Unicode character U+%04X", r))
			if hidden == nil {
				hidden = make(map[rune]bool)
			}
			hidden[r] = true
		}
	}
	if commented {
		report(number, "raw HTML comment (can hide instructions)")
	}
	if conflictMarker.Match(line.raw) {
		report(number, "unresolved merge conflict marker")
	}
	if !line.hasNewline {
		report(number, "missing final newline")
	}
}

func hiddenRune(r rune) bool {
	// Unicode 17 Default_Ignorable_Code_Point, plus control characters and
	// Braille Pattern Blank. Tabs and line endings are handled as text layout.
	// https://www.unicode.org/Public/17.0.0/ucd/DerivedCoreProperties.txt
	return (unicode.IsControl(r) && r != '\t') ||
		r == 0x00AD || r == 0x034F || r == 0x061C ||
		r >= 0x115F && r <= 0x1160 ||
		r >= 0x17B4 && r <= 0x17B5 ||
		r >= 0x180B && r <= 0x180F ||
		r >= 0x200B && r <= 0x200F ||
		r >= 0x202A && r <= 0x202E ||
		r >= 0x2060 && r <= 0x206F ||
		r == 0x2800 || r == 0x3164 ||
		r >= 0xFE00 && r <= 0xFE0F ||
		r == 0xFEFF || r == 0xFFA0 ||
		r >= 0xFFF0 && r <= 0xFFF8 ||
		r >= 0x1BCA0 && r <= 0x1BCA3 ||
		r >= 0x1D173 && r <= 0x1D17A ||
		r >= 0xE0000 && r <= 0xE0FFF
}
