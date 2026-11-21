package pipeline

import (
	"sort"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/langjs"
	"github.com/zazzcode/zazzles/scan/internal/langphp"
	"github.com/zazzcode/zazzles/scan/internal/langpy"
	"github.com/zazzcode/zazzles/scan/internal/parse"
	"github.com/zazzcode/zazzles/scan/internal/walk"
)

// Routes scans root and returns a syntactic route inventory. It keeps its own
// walk, appends the JS/TS, Python and PHP parts in that order, then sorts
// routes and gaps by file, byte offset and path or kind.
func Routes(root string) (*analysis.RouteInventory, error) {
	parsed, err := walk.Walk(root, walk.Options{})
	if err != nil {
		return nil, err
	}
	inv := parse.Inventory{Root: root, Files: parsed.Files}
	out := &analysis.RouteInventory{
		SchemaVersion: analysis.RouteSchemaVersion,
		Root:          root,
		Routes:        []analysis.Route{},
		Gaps:          []analysis.Gap{},
	}
	for _, part := range []func(parse.Inventory) ([]analysis.Route, []analysis.Gap, error){langjs.Routes, langpy.Routes, langphp.Routes} {
		routes, gaps, err := part(inv)
		if err != nil {
			return nil, err
		}
		out.Routes = append(out.Routes, routes...)
		out.Gaps = append(out.Gaps, gaps...)
	}
	sort.Slice(out.Routes, func(i, j int) bool {
		if out.Routes[i].Registration.File != out.Routes[j].Registration.File {
			return out.Routes[i].Registration.File < out.Routes[j].Registration.File
		}
		if out.Routes[i].Registration.StartByte != out.Routes[j].Registration.StartByte {
			return out.Routes[i].Registration.StartByte < out.Routes[j].Registration.StartByte
		}
		return out.Routes[i].PathPattern < out.Routes[j].PathPattern
	})
	sort.Slice(out.Gaps, func(i, j int) bool {
		if out.Gaps[i].At.File != out.Gaps[j].At.File {
			return out.Gaps[i].At.File < out.Gaps[j].At.File
		}
		if out.Gaps[i].At.StartByte != out.Gaps[j].At.StartByte {
			return out.Gaps[i].At.StartByte < out.Gaps[j].At.StartByte
		}
		return out.Gaps[i].Kind < out.Gaps[j].Kind
	})
	return out, nil
}
