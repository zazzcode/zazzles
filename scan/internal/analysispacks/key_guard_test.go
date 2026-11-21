package analysispacks

import (
	"slices"
	"testing"
)

func TestPollutionKeyListing(t *testing.T) {
	for _, tt := range []struct {
		name   string
		denied []string
		routes []string
	}{
		{"no exclusions", nil, []string{"__proto__", "constructor"}},
		{"__proto__", []string{"__proto__"}, []string{"constructor"}},
		{"constructor", []string{"constructor"}, []string{"__proto__"}},
		{"prototype", []string{"prototype"}, []string{"__proto__"}},
		{"__proto__ and constructor", []string{"constructor", "__proto__"}, nil},
		{"__proto__ and prototype", []string{"prototype", "__proto__"}, nil},
		{"constructor and prototype", []string{"prototype", "constructor"}, []string{"__proto__"}},
		{"all excluded", []string{"__proto__", "constructor", "prototype"}, nil},
		{"unrecognized name", []string{"unrelated"}, []string{"__proto__", "constructor"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			blocked, open := ListPrototypeKeys(tt.denied)
			if len(blocked)+len(open) != 3 || !slices.Equal(OpenPrototypeRoutes(open, 0), tt.routes) {
				t.Fatalf("invalid listing: blocked %v, open %v", blocked, open)
			}
			want := []string(nil)
			if slices.Contains(tt.routes, "__proto__") {
				want = append(want, "__proto__")
			}
			if got := OpenPrototypeRoutes(open, 2); !slices.Equal(got, want) {
				t.Fatalf("two-level routes %v, want %v", got, want)
			}
		})
	}
}
