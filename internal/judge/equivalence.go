package judge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/zazzcode/zazzles/internal/analysis"
)

// EquivalenceSignature hashes the selected provider request after normalizing
// invocation identity and unreferenced registration coordinates. Unknown facts
// remain in the signature so new wire fields conservatively split contexts.
func (c *Client) EquivalenceSignature(u analysis.CandidateUse) (string, error) {
	payload, err := c.payloadForm(u, false)
	if err != nil {
		return "", err
	}
	var request map[string]any
	if err = json.Unmarshal(payload, &request); err != nil {
		return "", err
	}
	field := "input"
	if c.provider == "jev" {
		field = "state"
	}
	var input map[string]any
	if err = json.Unmarshal([]byte(request[field].(string)), &input); err != nil {
		return "", err
	}
	use := input["use"].(map[string]any)
	normalizeBundle(use)
	// Preserve the equality pattern across invocation, control, transport and
	// path references, using the same aliases as the sent identity projection.
	localIdentity(use)
	request[field] = input
	data, err := json.Marshal(request)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:]), nil
}

func normalizeBundle(use map[string]any) {
	invocation, _ := use["invocation"].(map[string]any)
	http, _ := invocation["http"].(map[string]any)
	path, _ := http["path"].(string)
	sourcePath, _ := http["source_path"].(string)
	sensitive := routeMetadataSensitive(use)
	protected, protectedSpans := registrationProtection(use, invocation)
	registrationSpans := normalizeEvidence(use, protected, protectedSpans, path, sourcePath, sensitive)
	delete(use, "source_excerpts")
	// The compact request omits this derived graph. Its copy of the entry or
	// context must not turn a single occurrence into a recurring identifier.
	if graph, ok := use["trace_graph"].(map[string]any); ok {
		delete(graph, "entry")
		delete(graph, "invocation_context_id")
	}
	normalizeRouteCoordinates(use, http, path, sourcePath, sensitive)
	normalizeGapCoordinates(use, registrationSpans)
}

func registrationProtection(use, invocation map[string]any) (map[string]bool, map[string]bool) {
	protected := map[string]bool{}
	protectedSpans := map[string]bool{}
	resolved := map[string]bool{}
	if gaps, ok := use["resolved_gaps"].([]any); ok {
		for _, gap := range gaps {
			b, _ := json.Marshal(gap)
			resolved[string(b)] = true
		}
	}
	gapCollections := []any{invocation["entry_gaps"], invocation["dispatch_gaps"], use["blocking_gaps"], use["coverage_gaps"]}
	for _, collection := range gapCollections {
		if gaps, ok := collection.([]any); ok {
			for _, gap := range gaps {
				encoded, _ := json.Marshal(gap)
				if resolved[string(encoded)] {
					continue
				}
				if g, ok := gap.(map[string]any); ok {
					at, _ := json.Marshal(g["at"])
					protectedSpans[string(at)] = true
				}
			}
		}
	}

	var protect func(any)
	protect = func(v any) {
		switch x := v.(type) {
		case string:
			protected[x] = true
		case []any:
			for _, v := range x {
				protect(v)
			}
		case map[string]any:
			for _, v := range x {
				protect(v)
			}
		}
	}
	protect(invocation["conditions"])
	for _, key := range []string{"controls", "stages"} {
		if f, ok := use["input_facts"].(map[string]any); ok {
			protect(f[key])
		}
	}
	if controls, ok := invocation["controls"].([]any); ok {
		for _, v := range controls {
			if m, ok := v.(map[string]any); ok {
				protect(m["evidence"])
			}
		}
	}

	return protected, protectedSpans
}

func normalizeEvidence(use map[string]any, protected, protectedSpans map[string]bool, path, sourcePath string, sensitive bool) map[string]bool {
	evidence, _ := use["evidence"].([]any)
	excerpts, _ := use["source_excerpts"].([]any)
	registrationSpans := map[string]bool{}
	for i, v := range evidence {
		e := v.(map[string]any)
		id := fmt.Sprintf("e%d", i)
		kind, _ := e["kind"].(string)
		// Preserve the complete model-visible excerpt, including containing controls.
		if ref, ok := e["text_ref"].(string); ok {
			var index int
			if _, err := fmt.Sscanf(ref, "s%d", &index); err == nil && index >= 0 && index < len(excerpts) {
				e["source_excerpt"] = excerpts[index]
			}
			delete(e, "text_ref")
		}
		spanKey, _ := json.Marshal(e["span"])
		if !sensitive && !protected[id] && !protectedSpans[string(spanKey)] && (kind == "entry_registration" || kind == "route_registration" || kind == "registration") {
			// Keep registration syntax (including middleware and converters), replacing
			// only the literal route coordinate. Unknown syntax stays distinct.
			if excerpt, ok := e["source_excerpt"].(map[string]any); ok {
				span, _ := e["span"].(map[string]any)
				outer, _ := excerpt["span"].(map[string]any)
				if equalJSON(span, outer) {
					text, _ := excerpt["text"].(string)
					text = normalizeRouteLiteral(text, path, sourcePath)

					e["text"] = text
					delete(e, "source_excerpt")
					encoded, _ := json.Marshal(span)
					registrationSpans[string(encoded)] = true
					delete(e, "span")
					delete(e, "start_column")
					delete(e, "end_column")
				}
			}
		}
	}
	return registrationSpans
}

func normalizeRouteCoordinates(use, http map[string]any, path, sourcePath string, sensitive bool) {
	if !sensitive && !strings.ContainsAny(path+sourcePath, "<>:") {
		delete(http, "path")
		delete(http, "source_path")
	}
	if check, ok := use["declared_requirement"].(map[string]any); ok && !sensitive {
		delete(check, "path")
		delete(check, "method")
	}
}

func normalizeGapCoordinates(use map[string]any, registrationSpans map[string]bool) {
	var normalize func(any) any
	normalize = func(v any) any {
		switch x := v.(type) {
		case []any:
			for i, v := range x {
				x[i] = normalize(v)
			}
		case map[string]any:
			if at, ok := x["at"].(map[string]any); ok {
				encoded, _ := json.Marshal(at)
				if registrationSpans[string(encoded)] {
					x["at"] = "entry registration"
				}
			}
			for k, v := range x {
				x[k] = normalize(v)
			}
		}
		return v
	}
	normalize(use)
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// Rewriting only an unambiguous first route argument avoids erasing a policy
// argument that happens to equal the route (for example acl('/admin')).
func normalizeRouteLiteral(text string, routes ...string) string {
	for _, route := range routes {
		if route == "" || strings.ContainsAny(route, "<>:") {
			continue
		}
		count, index, quoted := 0, -1, ""
		for _, q := range []string{"'", `"`, "`"} {
			needle := q + route + q
			n := strings.Count(text, needle)
			count += n
			if n > 0 {
				index = strings.Index(text, needle)
				quoted = needle
			}
		}
		if count != 1 {
			continue
		}
		prefix := text[:index]
		if strings.Count(prefix, "(") != 1 || !strings.HasSuffix(strings.TrimSpace(prefix), "(") {
			continue
		}
		return text[:index] + quoted[:1] + "<route>" + quoted[:1] + text[index+len(quoted):]
	}
	return text
}

var routeMetadataAccess = regexp.MustCompile(`(?i)(\b\w*(path|url|route|endpoint|method|environ|scope)\w*\b|\[|\bReflect\s*\.)`)

// A callable can branch on route metadata without transferring it to the sink.
// Keep route coordinates whenever source might inspect them, even if that means
// missing an otherwise equivalent context.
func routeMetadataSensitive(use map[string]any) bool {
	receivers := requestReceivers(use)
	for _, key := range []string{"evidence", "source_excerpts"} {
		if rows, ok := use[key].([]any); ok {
			for _, row := range rows {
				if e, ok := row.(map[string]any); ok {
					if text, ok := e["text"].(string); ok && (routeMetadataAccess.MatchString(text) || requestObjectEscapes(text, receivers)) {
						return true
					}
				}
			}
		}
	}
	return false
}

type requestReceiver struct {
	name     string
	mentions *regexp.Regexp
}

func requestReceivers(use map[string]any) []requestReceiver {
	invocation, _ := use["invocation"].(map[string]any)
	inputs, _ := invocation["inputs"].([]any)
	var names []requestReceiver
	for _, input := range inputs {
		item, _ := input.(map[string]any)
		role, _ := item["role"].(string)
		if !strings.HasPrefix(role, "http.") || role == "http.response" {
			continue
		}
		parameter, _ := item["parameter"].(string)
		name, _, _ := strings.Cut(parameter, ".")
		if name != "" {
			names = append(names, requestReceiver{name, regexp.MustCompile(regexp.QuoteMeta(name))})
		}
	}
	return names
}

// Only modeled input containers may be read without retaining route coordinates.
// Passing, aliasing or inspecting the whole request could expose arbitrary route
// metadata, so those contexts conservatively keep their original coordinates.
func requestObjectEscapes(text string, receivers []requestReceiver) bool {
	allowed := map[string]bool{"query": true, "body": true, "params": true, "headers": true, "cookies": true, "args": true, "form": true, "values": true, "GET": true, "POST": true, "data": true, "json": true}
	for _, receiver := range receivers {
		if strings.TrimSpace(text) == receiver.name {
			continue
		} // parameter-binding excerpt
		mentions := receiver.mentions.FindAllStringIndex(text, -1)
		for _, at := range mentions {
			if at[0] > 0 && requestIdentifierByte(text[at[0]-1]) || at[1] < len(text) && requestIdentifierByte(text[at[1]]) {
				continue
			}
			rest := strings.TrimSpace(text[at[1]:])
			if strings.HasPrefix(rest, "?.") {
				rest = rest[1:]
			}
			if !strings.HasPrefix(rest, ".") {
				return true
			}
			property := strings.TrimSpace(rest[1:])
			end := 0
			for end < len(property) && (property[end] >= 'a' && property[end] <= 'z' || property[end] >= 'A' && property[end] <= 'Z' || property[end] == '_' || property[end] >= '0' && property[end] <= '9') {
				end++
			}
			if !allowed[property[:end]] {
				return true
			}
		}
	}
	return false
}

func requestIdentifierByte(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || b == '_' || b == '$'
}
