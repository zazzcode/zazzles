package main

import "strings"

// fixtureRoot maps a fixture name qualified by its tree ("python/outbound",
// "javascript/grpc", "mixed/three-language", "string-flow") to its testdata
// directory: Python fixtures live in internal/langpy, the multi-runner mixed
// fixtures in internal/pipeline, and JS/TS fixtures in internal/langjs.
func fixtureRoot(name string) string {
	if rest, ok := strings.CutPrefix(name, "python/"); ok {
		return "../../internal/langpy/testdata/" + rest
	}
	if strings.HasPrefix(name, "mixed/") {
		return "../../internal/pipeline/testdata/" + name
	}
	return "../../internal/langjs/testdata/" + name
}
