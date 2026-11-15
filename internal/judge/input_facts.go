package judge

import (
	"github.com/zazzcode/zazzles/internal/analysis"
	"reflect"
)

func wireInputFacts(use analysis.CandidateUse, ref func(analysis.Evidence) string) any {
	f := use.InputFacts
	if f == nil {
		return nil
	}
	values := []map[string]any{}
	for _, v := range f.Values {
		transfers := []string{}
		for _, e := range v.Transfers {
			transfers = append(transfers, ref(e))
		}
		value := map[string]any{"dependency": v.Dependency, "origin": v.Origin, "initial_type": v.InitialType, "sink_type": v.SinkType, "source": ref(v.Source), "transfers": transfers}
		if v.Dependency >= 0 && v.Dependency < len(use.Dependencies) {
			d := use.Dependencies[v.Dependency]
			if reflect.DeepEqual(v.Source, d.Source) && reflect.DeepEqual(v.Transfers, d.Transfers) {
				delete(value, "source")
				delete(value, "transfers")
				value["path_from_dependency"] = true
			}
		}
		values = append(values, value)
	}
	controls := []string{}
	for _, e := range f.Controls {
		controls = append(controls, ref(e))
	}
	stages := []map[string]any{}
	for _, stage := range f.Stages {
		stages = append(stages, map[string]any{"name": stage.Name, "order": stage.Order, "scope": stage.Scope, "evidence": ref(stage.Evidence)})
	}
	return map[string]any{"version": f.Version, "acquisition": f.Acquisition, "framework": f.Framework, "binding": ref(f.Binding), "values": values, "controls": controls, "stages": stages, "gaps": f.Gaps}
}
