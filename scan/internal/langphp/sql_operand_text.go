package langphp

import "strings"

// phpOperandMark stands for an operand in SQL text.
const phpOperandMark = 1

// phpSQLToken is a word, a symbol or a literal of one SQL statement. Words are
// lower case; a literal is "'" and a quoted identifier "`".
type phpSQLToken struct {
	text     string
	operands int
}

// phpOperandFollowers are the words that may follow a literal with an operand.
var phpOperandFollowers = map[string]bool{")": true, ",": true, "and": true, "or": true, "where": true, "order": true, "group": true, "limit": true}

// phpComparators are the symbols and words an operand literal may be compared with.
var phpComparators = map[string]bool{"=": true, "<>": true, "!=": true, "<": true, ">": true, "<=": true, ">=": true, "like": true}

// phpQuotedOperands reports one plain data statement in which every operand is
// alone in a single-quoted literal that is a compared or listed value. Each token
// must be known: a function call, a comment, a backslash, a double quote, a
// variable, an introducer, INTO of a SELECT or a second statement fails.
func phpQuotedOperands(sql string) bool {
	tokens := phpSQLTokens(sql)
	if len(tokens) == 0 {
		return false
	}
	for len(tokens) > 1 && tokens[len(tokens)-1].text == ";" {
		tokens = tokens[:len(tokens)-1]
	}
	word := func(i int) string { return tokens[i].text }
	switch word(0) {
	case "select", "update", "delete", "insert", "replace":
	default:
		return false
	}
	insert := word(0) == "insert" || word(0) == "replace"
	var open []string
	for i, t := range tokens {
		list := len(open) > 0 && open[len(open)-1] == "list"
		switch {
		case t.operands > 0:
			before := word(i - 1)
			if t.operands > 1 || !phpComparators[before] && !(list && (before == "(" || before == ",")) || i+1 < len(tokens) && !phpOperandFollowers[word(i+1)] {
				return false
			}
		case t.text == ";" || t.text == "into" && !(insert && i == 1):
			return false
		case t.text == "(":
			kind := phpParenthesis(word, i)
			if kind == "" {
				return false
			}
			open = append(open, kind)
		case t.text == ")":
			if len(open) == 0 {
				return false
			}
			open = open[:len(open)-1]
		}
	}
	return len(open) == 0
}

// phpParenthesis names the group that the parenthesis at i opens, or "" when it may
// be the arguments of a function. INTO stands second only in an INSERT or REPLACE.
func phpParenthesis(word func(int) string, i int) string {
	switch word(i - 1) {
	case "values", "in":
		return "list"
	case ",":
		if word(i-2) == ")" {
			return "list"
		}
	case "(", "and", "or", "not", "where", "on":
		return "group"
	default:
		if i == 3 && word(1) == "into" || i == 5 && word(1) == "into" && word(3) == "." {
			return "columns"
		}
	}
	return ""
}

// phpSQLTokens splits SQL text. A byte outside its small alphabet leaves none.
func phpSQLTokens(sql string) []phpSQLToken {
	var out []phpSQLToken
	for i := 0; i < len(sql); {
		c, start := sql[i], i
		switch {
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			i++
			continue
		case c == '\'' || c == '`':
			t := phpSQLToken{text: sql[i : i+1]}
			for i++; ; i++ {
				if i >= len(sql) || sql[i] == '\\' || sql[i] >= 0x7f || sql[i] < ' ' && sql[i] != phpOperandMark && !strings.ContainsRune("\t\r\n", rune(sql[i])) {
					return nil
				}
				if sql[i] == phpOperandMark {
					t.operands++
				}
				if sql[i] != c {
					continue
				}
				if i++; i >= len(sql) || sql[i] != c {
					break
				}
			}
			if c == '`' && t.operands > 0 {
				return nil
			}
			out = append(out, t)
			continue
		case phpSQLWordByte(c):
			for i < len(sql) && phpSQLWordByte(sql[i]) {
				i++
			}
		case strings.IndexByte("=<>!", c) >= 0:
			for i < len(sql) && strings.IndexByte("=<>!", sql[i]) >= 0 {
				i++
			}
		case strings.IndexByte("(),.*;", c) >= 0:
			i++
		default:
			return nil
		}
		out = append(out, phpSQLToken{text: strings.ToLower(sql[start:i])})
	}
	return out
}

func phpSQLWordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}
