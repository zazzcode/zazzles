package parse

import (
	"strings"
	"unicode"
)

// Field-key lexicons produce hints for judgment, never an established data class.
var credentialTokens = map[string]bool{"password": true, "passwd": true, "pwd": true, "passphrase": true, "secret": true, "token": true, "otp": true, "totp": true, "mfa": true, "credential": true, "credentials": true, "jwt": true, "bearer": true, "apikey": true, "cvv": true}

var credentialPairs = map[string]bool{"apikey": true, "privatekey": true, "sessionid": true, "accesskey": true}

var credentialSubstrings = []string{"password", "passwd", "secret"}

var personalTokens = map[string]bool{"email": true, "phone": true, "mobile": true, "ssn": true, "dob": true, "birthdate": true, "birthday": true, "iban": true, "passport": true}

var personalPairs = map[string]bool{"creditcard": true, "cardnumber": true}

func logDataClass(container, key string) (string, string) {
	container = strings.ToLower(container)
	if key == "" {
		switch container {
		case "body", "query", "headers", "cookies":
			return "container", ""
		}
		return "", ""
	}
	if container == "headers" {
		switch strings.ToLower(key) {
		case "authorization", "proxy-authorization", "cookie":
			return "protocol_credential", ""
		}
	}
	if container == "cookies" {
		return "hint", "cookie"
	}
	if hint := lexiconHint(key); hint != "" {
		return "hint", hint
	}
	return "", ""
}

func lexiconHint(key string) string {
	tokens := nameTokens(key)
	for i, t := range tokens {
		pair := ""
		if i+1 < len(tokens) {
			pair = t + tokens[i+1]
		}
		if credentialTokens[t] || credentialPairs[pair] {
			return "credential"
		}
		for _, sub := range credentialSubstrings {
			if strings.Contains(t, sub) {
				return "credential"
			}
		}
		if personalTokens[t] || personalPairs[pair] {
			return "personal-data"
		}
	}
	return ""
}

// nameTokens splits camelCase, snake_case and kebab-case keys into lower-case tokens.
func nameTokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	rs := []rune(s)
	for i, r := range rs {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			flush()
		case unicode.IsUpper(r) && i > 0 && (unicode.IsLower(rs[i-1]) || unicode.IsDigit(rs[i-1])):
			flush()
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return out
}
