package main

import "strings"

// fixtureRoot maps a language-qualified fixture name ("python/outbound",
// "javascript/grpc") to its testdata directory: Python fixtures live in
// internal/langpy, JS/TS and mixed fixtures in internal/parse.
func fixtureRoot(name string) string {
	if rest, ok := strings.CutPrefix(name, "python/"); ok {
		return "../../internal/langpy/testdata/" + rest
	}
	return "../../internal/parse/testdata/" + name
}
