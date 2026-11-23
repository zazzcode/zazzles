package deployconf

import "strings"

// PHPIni reads the directives the checks name. Both ';' and '#' start a
// comment in php.ini.
func PHPIni(file string, src []byte) ([]Directive, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	var out []Directive
	for _, row := range physicalLines(src) {
		name, val, ok := strings.Cut(stripComment(row.text, ";#"), "=")
		if !ok {
			continue
		}
		name = strings.ToLower(strings.TrimSpace(name))
		switch name {
		case "display_errors", "session.cookie_httponly", "session.cookie_secure":
			out = append(out, Directive{File: file, Line: row.num, Name: name, Values: []string{unquote(strings.TrimSpace(val))}})
		}
	}
	return out, nil
}
