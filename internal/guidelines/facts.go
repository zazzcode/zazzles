package guidelines

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

// The fact notes own the interpretation of fixed scanner facts. A request sends
// only the notes its coded model facts name, so a request without a coded fact
// is unchanged by this document.
//
//go:embed facts.md
var factsDocument string

var (
	factNotes   map[string]string
	factOrder   []string
	factVersion string
	factPrefix  = regexp.MustCompile(`^([a-z][a-z0-9_]*)(?::|$)`)
)

func init() {
	item, err := parse(factsDocument)
	if err != nil {
		panic("facts.md: " + err.Error())
	}
	factVersion = item.ID + " v" + item.Version
	factNotes = map[string]string{}
	note := regexp.MustCompile("^- `([a-z][a-z0-9_]*)`: (.+)$")
	for _, line := range strings.Split(factsDocument, "\n") {
		m := note.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if _, dup := factNotes[m[1]]; dup {
			panic("facts.md: duplicate fact code " + m[1])
		}
		factNotes[m[1]] = m[2]
		factOrder = append(factOrder, m[1])
	}
	if len(factNotes) == 0 {
		panic("facts.md: no fact codes")
	}
}

// FactCode returns the code a coded model fact begins with: a lower-case
// identifier that is the whole fact or is followed by a colon.
func FactCode(fact string) (string, bool) {
	m := factPrefix.FindStringSubmatch(fact)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// KnownFact reports whether a code has a note.
func KnownFact(code string) bool {
	_, ok := factNotes[code]
	return ok
}

// FactNotes returns the guidance section interpreting the coded facts among
// model facts, in the document's order, or "" when none is coded. An unknown
// code is an error: a fact must never reach the model without its owner.
func FactNotes(facts []string) (string, error) {
	used := map[string]bool{}
	for _, fact := range facts {
		code, ok := FactCode(fact)
		if !ok {
			continue
		}
		if !KnownFact(code) {
			return "", fmt.Errorf("model fact code %q has no guidance note", code)
		}
		used[code] = true
	}
	if len(used) == 0 {
		return "", nil
	}
	var b strings.Builder
	b.WriteString("## Fact codes (" + factVersion + ")\n\nInterpret each coded model_facts entry here; text after a code names its expression and file.\n")
	for _, code := range factOrder {
		if used[code] {
			b.WriteString("\n- `" + code + "`: " + factNotes[code])
		}
	}
	return b.String(), nil
}
