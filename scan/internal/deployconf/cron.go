package deployconf

import (
	"strings"
	"unicode"
)

// Cron reads one crontab file. system selects the form with a user field
// after the schedule. A schedule is five fields or one @nickname. Cron has
// no line continuation, and '#' starts a comment only on its own line.
func Cron(file string, src []byte, system bool) []ScheduleLine {
	if tooBig(src) {
		return nil
	}
	var out []ScheduleLine
	for _, row := range physicalLines(src) {
		text := strings.TrimSpace(row.text)
		if text == "" || strings.HasPrefix(text, "#") || envAssign(text) {
			continue
		}
		toks := fieldsQuoted(text)
		need := 5
		if strings.HasPrefix(toks[0], "@") {
			need = 1
		}
		user := ""
		if system {
			if len(toks) <= need {
				continue
			}
			user = unquote(toks[need])
			if strings.Contains(user, "/") {
				continue
			}
			need++
		}
		if len(toks) <= need {
			continue
		}
		cmd := strings.Join(unquoteAll(toks[need:]), " ")
		out = append(out, ScheduleLine{File: file, Line: row.num, User: user, Command: cmd, System: system})
	}
	return out
}

// envAssign reports a NAME=value line of a crontab.
func envAssign(text string) bool {
	name, _, ok := strings.Cut(text, "=")
	name = strings.TrimSpace(name)
	if !ok || name == "" {
		return false
	}
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}
