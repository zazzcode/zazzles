package judge

import "github.com/zazzcode/zazzles/scan/internal/analysis"

// wireInvocation projects canonical read views, referring to deduplicated source
// evidence rather than sending another copy of handler bodies with each binding.
func wireInvocation(use analysis.CandidateUse, ref func(analysis.Evidence) string) any {
	uniqueGaps := func(items []analysis.Gap) []analysis.Gap {
		var out []analysis.Gap
		for _, g := range items {
			duplicate := false
			if c := use.Completeness; c != nil {
				for _, collection := range [][]analysis.Gap{c.Blockers, c.Coverage, c.Resolved} {
					for _, known := range collection {
						duplicate = duplicate || g == known
					}
				}
			}
			if !duplicate {
				out = append(out, g)
			}
		}
		return out
	}
	out := map[string]any{"assessment_scope": "This candidate invocation only; not protection of the entire entry or all dispatch alternatives", "entry_id": use.EntryID, "invocation_context_id": use.InvocationContextID, "entry_kind": use.EntryKind}
	if e := use.EntryFacts; e != nil {
		out["instance_id"] = e.InstanceID
		out["registration_evidence"] = ref(e.Location)
		out["http"] = e.HTTP
		out["browser"] = e.Browser
		out["graphql"] = e.GraphQL
		out["grpc"] = e.GRPC
		out["entry_gaps"] = uniqueGaps(e.Gaps)
		transports := []any{}
		for _, transport := range e.Transports {
			evidence := []string{}
			for _, e := range transport.Evidence {
				evidence = append(evidence, ref(e))
			}
			transports = append(transports, map[string]any{"kind": transport.Kind, "entry_id": transport.EntryID, "evidence": evidence})
		}
		out["transports"] = transports
	}
	if b := use.DispatchFacts; b != nil {
		out["dispatch_binding_id"] = b.ID
		out["registration_id"] = b.RegistrationID
		out["callable_id"] = b.CallableID
		conditions := []string{}
		for _, e := range b.Conditions {
			conditions = append(conditions, ref(e))
		}
		out["conditions"] = conditions
		out["resolution"] = b.Resolution
		out["mechanism"] = b.Mechanism
		out["stage"] = b.Stage
		out["alternative"] = b.Alternative
		out["dispatch_gaps"] = uniqueGaps(b.Gaps)
	}
	if ctx := use.InvocationFacts; ctx != nil {
		input := func(v analysis.InputBinding) map[string]any {
			evidence := []string{}
			for _, e := range v.Origin.Evidence {
				evidence = append(evidence, ref(e))
			}
			return map[string]any{"constant": v.Constant, "role": v.Role, "parameter": v.Parameter, "projection": v.Projection, "origin_kind": v.Origin.Kind, "origin_evidence": evidence, "related_entry_id": v.Origin.RelatedEntryID}
		}
		inputs := []any{}
		for _, v := range ctx.Inputs {
			inputs = append(inputs, input(v))
		}
		out["inputs"] = inputs
		closures := []any{}
		for _, v := range ctx.Closures {
			closures = append(closures, input(v))
		}
		out["closures"] = closures
		if ctx.Receiver != nil {
			out["receiver"] = input(*ctx.Receiver)
		}
		controls := []any{}
		for _, v := range ctx.Controls {
			controls = append(controls, map[string]string{"invocation_context_id": v.InvocationContextID, "dispatch_binding_id": v.DispatchBindingID, "evidence": ref(v.Evidence)})
		}
		out["controls"] = controls
		out["context_gaps"] = uniqueGaps(ctx.Gaps)
	}
	return out
}
