package deployconf

import "strings"

// EnvKeys returns APP_ENV and APP_DEBUG only, each with its line. Every
// other line is discarded before a value is stored. A dotenv file has no
// line continuation, so each physical line stands alone, and a value that
// is not one plain word is discarded too: neither key legitimately holds
// anything else, and nothing of another variable can ride along.
func EnvKeys(file string, src []byte) (map[string]EnvSetting, []Gap) {
	if tooBig(src) {
		return nil, unread(file)
	}
	out := map[string]EnvSetting{}
	for _, row := range physicalLines(src) {
		text := strings.TrimSpace(row.text)
		text = strings.TrimSpace(strings.TrimPrefix(text, "export "))
		key, rest, ok := strings.Cut(text, "=")
		key = strings.TrimSpace(key)
		if !ok || (key != "APP_ENV" && key != "APP_DEBUG") {
			continue
		}
		value := unquote(strings.TrimSpace(stripComment(rest, "#")))
		if !plainWord(value) {
			delete(out, key)
			continue
		}
		out[key] = EnvSetting{Key: key, Value: value, Line: row.num}
	}
	return out, nil
}

func plainWord(s string) bool {
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
			return false
		}
	}
	return true
}
