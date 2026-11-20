package judge

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Request-local identity (judge-request-size-reduction D-2). The only thing a
// hash-based identifier tells the model is whether two of them are equal, so
// the model-facing projection keeps exactly that: an identifier that occurs
// twice or more becomes one short alias (i0, i1, ... in order of first
// occurrence), one that occurs once leaves with its key, and a list of
// identifiers keeps the aliases of members that occur elsewhere plus a count
// of all members. CandidateUse, traces and reports keep every identifier.

// hashIdentifier is a <kind>:v1:<64 hex> identifier.
var hashIdentifier = regexp.MustCompile(`^[a-z_]+:v1:[0-9a-f]{64}$`)

// identityKeys hold identifiers whatever their form.
var identityKeys = map[string]bool{"instance_id": true, "candidate_id": true}

// sourceKeys hold source text, which is never rewritten even when it contains
// a hash literal. evidence and source_excerpts are skipped at the top level
// of the bundle; text wherever it appears.
var sourceKeys = map[string]bool{"evidence": true, "source_excerpts": true}

type identityMode int

const (
	// aliasIdentity is the sent form: recurring identifiers become aliases.
	aliasIdentity identityMode = iota
	// keepIdentity drops single identifiers and reduces lists like
	// aliasIdentity but keeps recurring values, so a later normalization can
	// still recognize them.
	keepIdentity
	// renumberIdentity aliases every remaining identifier and drops none.
	renumberIdentity
)

// localIdentity rewrites hash-based identifiers in a decoded request bundle:
// recurring ones become aliases, single ones are removed, lists gain a count.
// The bundle is rewritten in place and returned.
func localIdentity(bundle map[string]any) map[string]any {
	return projectIdentity(bundle, aliasIdentity)
}

func projectIdentity(bundle map[string]any, mode identityMode) map[string]any {
	counts := map[string]int{}
	aliases := map[string]string{}
	walkIdentity(bundle, true, func(id string) {
		counts[id]++
		if _, ok := aliases[id]; !ok {
			aliases[id] = "" // numbered below, in first-occurrence order
		}
	})
	next := 0
	walkIdentity(bundle, true, func(id string) {
		if aliases[id] == "" && (counts[id] >= 2 || mode == renumberIdentity) {
			aliases[id] = fmt.Sprintf("i%d", next)
			next++
		}
	})
	value := func(id string) (string, bool) {
		alias := aliases[id]
		if alias == "" {
			return "", false
		}
		if mode == keepIdentity {
			return id, true
		}
		return alias, true
	}
	rewriteIdentity(bundle, true, mode, value)
	return bundle
}

// identifierAt reports whether v, under key, is an identifier.
func identifierAt(key string, v any) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return "", false
	}
	return s, identityKeys[key] || hashIdentifier.MatchString(s)
}

// walkIdentity visits identifiers in a fixed order: map keys sorted (the
// order json.Marshal writes them), list elements in order.
func walkIdentity(v any, top bool, visit func(string)) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if k == "text" || top && sourceKeys[k] {
				continue
			}
			if id, ok := identifierAt(k, x[k]); ok {
				visit(id)
				continue
			}
			walkIdentity(x[k], false, visit)
		}
	case []any:
		for _, e := range x {
			if id, ok := identifierAt("", e); ok {
				visit(id)
				continue
			}
			walkIdentity(e, false, visit)
		}
	}
}

func rewriteIdentity(v any, top bool, mode identityMode, value func(string) (string, bool)) {
	switch x := v.(type) {
	case map[string]any:
		for _, k := range sortedKeys(x) {
			if k == "text" || top && sourceKeys[k] {
				continue
			}
			if id, ok := identifierAt(k, x[k]); ok {
				if alias, keep := value(id); keep {
					x[k] = alias
				} else {
					delete(x, k)
				}
				continue
			}
			if list, ok := identifierList(x[k]); ok && mode != renumberIdentity {
				kept := []any{}
				for _, id := range list {
					if alias, keep := value(id); keep {
						kept = append(kept, alias)
					}
				}
				x[countKey(k)] = len(list)
				if len(kept) > 0 {
					x[k] = kept
				} else {
					delete(x, k)
				}
				continue
			}
			rewriteIdentity(x[k], false, mode, value)
		}
	case []any:
		for i, e := range x {
			if id, ok := identifierAt("", e); ok {
				// A positional list cannot lose a member; an identifier in
				// a mixed list keeps an alias.
				if alias, keep := value(id); keep {
					x[i] = alias
				} else {
					x[i] = ""
				}
				continue
			}
			rewriteIdentity(e, false, mode, value)
		}
	}
}

// identifierList returns v's members when v is a non-empty list of identifiers.
func identifierList(v any) ([]string, bool) {
	list, ok := v.([]any)
	if !ok || len(list) == 0 {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		id, ok := identifierAt("", e)
		if !ok {
			return nil, false
		}
		out = append(out, id)
	}
	return out, true
}

// countKey names a list's member count: related_entries -> related_entry_count.
func countKey(key string) string {
	switch {
	case strings.HasSuffix(key, "ies"):
		key = strings.TrimSuffix(key, "ies") + "y"
	case strings.HasSuffix(key, "s"):
		key = strings.TrimSuffix(key, "s")
	}
	return key + "_count"
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
