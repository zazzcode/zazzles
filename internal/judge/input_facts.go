package judge

import "github.com/zazzcode/zazzles/internal/analysis"

func wireInputFacts(f *analysis.InputFacts, ref func(analysis.Evidence) string) any {
	if f == nil {
		return nil
	}
	values := []map[string]any{}
	for _, v := range f.Values {
		transfers := []string{}
		for _, e := range v.Transfers {
			transfers = append(transfers, ref(e))
		}
		values = append(values, map[string]any{"dependency": v.Dependency, "origin": v.Origin, "initial_type": v.InitialType, "sink_type": v.SinkType, "source": ref(v.Source), "transfers": transfers})
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
