package main

import (
	"bytes"
	"fmt"
	"regexp"
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
		{regexp.MustCompile(`(?i)\byou\s+are\s+now\s+(?:(?:an?|in)\s+)?(?:system|administrator|admin|developer|unrestricted|developer mode)\b|\[/?INST\]|<\|(?:im_start|im_end|system|assistant|user|start_header_id|end_header_id)\|>`), "possible prompt injection (role control)"},
		{regexp.MustCompile(`(?i)\bexfiltrate\s+(?:(?:the|all|any)\s+)*(?:secrets?|credentials?|tokens?|keys?|data)\b`), "possible prompt injection (data exfiltration)"},
		{regexp.MustCompile(`(?i)\b(?:curl|wget)\s+[^|]*\|\s*(?:(?:sudo|env)\s+)*(?:[\w./-]+/)?(?:ba|da|z|k)?sh\b`), "remote download piped into a shell"},
	}
)

// A nil span list means the entire file was added. Unchanged lines supply only
// the HTML comment state so an edit in an existing comment is still checked.
func lintLines(blob []byte, spans []lineSpan, report func(int, string)) {
	allLines := spans == nil
	inComment := false
	number := 0
	for line := range bytes.Lines(blob) {
		number++
		for len(spans) > 0 && spans[0].end <= number {
			spans = spans[1:]
		}
		if !allLines && len(spans) == 0 {
			break
		}
		terminator := line[len(line)-1] == '\n'
		line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
		commented := inComment
		for _, marker := range commentMarker.FindAll(line, -1) {
			inComment = marker[0] == '<'
			commented = commented || inComment
		}
		if allLines || spans[0].first <= number {
			lintLine(line, number, commented, terminator, report)
		}
	}
}

func lintLine(line []byte, number int, commented, terminator bool, report func(int, string)) {
	if !utf8.Valid(line) || bytes.IndexByte(line, 0) >= 0 {
		report(number, "expected UTF-8 text without NUL bytes")
	}
	var hidden map[rune]bool
	for _, r := range string(line) {
		if hiddenRune(r) && !hidden[r] {
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
	if conflictMarker.Match(line) {
		report(number, "unresolved merge conflict marker")
	}
	if !terminator {
		report(number, "missing final newline")
	}
	for _, rule := range promptRules {
		if rule.pattern.Match(line) {
			report(number, rule.message)
		}
	}
}

func hiddenRune(r rune) bool {
	return r == 0x00AD || r == 0x034F || r == 0x061C || r == 0x180E ||
		r >= 0x200B && r <= 0x200F ||
		r >= 0x202A && r <= 0x202E ||
		r >= 0x2060 && r <= 0x2064 ||
		r >= 0x2066 && r <= 0x2069 ||
		r == 0xFEFF ||
		r >= 0xE0000 && r <= 0xE007F
}
