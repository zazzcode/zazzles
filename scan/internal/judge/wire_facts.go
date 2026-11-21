package judge

import (
	"encoding/json"
	"fmt"
)

// wireContextFacts projects only CandidateUse.Context indices. Path flow controls
// index the guard table instead and must remain integers. Budgeting runs first.
func wireContextFacts(facts any, context []string, path bool) any {
	raw, _ := json.Marshal(facts)
	var out any
	if json.Unmarshal(raw, &out) != nil || out == nil {
		return nil
	}
	reference := func(v any) any {
		n, ok := v.(float64)
		if ok && n == float64(int(n)) && int(n) >= 0 && int(n) < len(context) {
			return context[int(n)]
		}
		// Invalid parser indices remain explicit rather than borrowing another item.
		return fmt.Sprintf("invalid_context:%v", v)
	}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case []any:
			for _, item := range x {
				visit(item)
			}
		case map[string]any:
			for k, item := range x {
				if k == "context" || (k == "controls" && !path) {
					if items, ok := item.([]any); ok {
						for i := range items {
							items[i] = reference(items[i])
						}
					} else {
						x[k] = reference(item)
					}
				} else {
					visit(item)
				}
			}
		}
	}
	visit(out)
	return out
}
