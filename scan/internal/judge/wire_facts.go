package judge

import (
	"encoding/json"
	"fmt"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
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

// wireExposure sends the exposure facts with guard evidence as eN references.
// Records of other families carry no exposure facts, so their bytes are unchanged.
func wireExposure(f *analysis.ExposureFacts, ref func(analysis.Evidence) string) any {
	if f == nil {
		return nil
	}
	guards := make([]map[string]string, 0, len(f.Guards))
	for _, g := range f.Guards {
		guards = append(guards, map[string]string{"kind": g.Kind, "evidence": ref(g)})
	}
	out := map[string]any{"operation": f.Operation, "subject": f.Subject, "entry_served": f.EntryServed, "guards": guards}
	if f.Flag != "" {
		out["flag"] = f.Flag
	}
	return out
}

// wireMassAssignment sends the key-controlled write facts with key guards and
// census evidence as eN references.
func wireMassAssignment(f *analysis.MassAssignmentFacts, ref func(analysis.Evidence) string) any {
	if f == nil {
		return nil
	}
	guards := make([]map[string]string, 0, len(f.KeyGuards))
	for _, g := range f.KeyGuards {
		guards = append(guards, map[string]string{"kind": g.Kind, "evidence": ref(g)})
	}
	fields := make([]map[string]any, 0, len(f.SecurityFields))
	for _, s := range f.SecurityFields {
		evidence := make([]string, 0, len(s.Evidence))
		for _, e := range s.Evidence {
			evidence = append(evidence, ref(e))
		}
		fields = append(fields, map[string]any{"storage_key": s.StorageKey, "roles": s.Roles, "evidence": evidence})
	}
	out := map[string]any{"shape": f.Shape, "target_class": f.TargetClass, "target_stored": f.TargetStored, "key_guards": guards, "security_fields": fields}
	if len(f.MappedFields) > 0 {
		out["mapped_fields"] = f.MappedFields
	}
	return out
}
