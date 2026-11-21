package langjs

import (
	"bytes"
	"encoding/json"
	"flag"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

var update = flag.Bool("update", false, "rewrite golden files")

// The sorted golden bytes of this fixture are pinned by internal/pipeline's
// TestExpressLoginGolden.
func TestExpressLoginGolden(t *testing.T) {
	got := mustScan(t, "testdata/express-login")

	var login *analysis.Route
	var profile *analysis.Route
	for i := range got.Routes {
		route := &got.Routes[i]
		if route.Method == "POST" && route.PathPattern == "/rest/user/login" {
			login = route
		}
		if route.Method == "GET" && route.PathPattern == "/rest/profile" {
			profile = route
		}
	}
	if login == nil {
		t.Fatal("missing POST /rest/user/login")
	}
	if login.Framework != "express" || login.Handler.Name != "login" {
		t.Fatalf("login route = %+v", login)
	}
	if !hasStep(login, "login") {
		t.Fatalf("login route steps = %+v", login.Steps)
	}
	if profile == nil || !hasCall(profile, "security.login") {
		t.Fatalf("profile route = %+v", profile)
	}
}

func TestChainedRoute(t *testing.T) {
	got := mustScan(t, "testdata/express-login")
	seen := map[int]string{}
	for _, method := range []string{"GET", "PUT", "DELETE"} {
		route := findRoute(got, "chain.js", method, "/api/items/:id")
		if route == nil {
			t.Errorf("missing %s /api/items/:id from chain.js", method)
			continue
		}
		if route.Steps[0].Symbol.Name != "route."+methodName(method) {
			t.Errorf("registration name = %q, want route.%s", route.Steps[0].Symbol.Name, methodName(method))
		}
		if prev, ok := seen[route.Registration.StartLine]; ok {
			t.Errorf("%s and %s share start line %d", prev, method, route.Registration.StartLine)
		}
		seen[route.Registration.StartLine] = method
	}
	for _, route := range got.Routes {
		if route.Registration.File == "chain.js" && route.PathPattern != "/api/items/:id" {
			t.Errorf("chained dynamic path produced %s %s", route.Method, route.PathPattern)
		}
	}
	if !hasGap(got, "dynamic_path", "chain.js") {
		t.Fatalf("gaps = %+v, want dynamic_path in chain.js", got.Gaps)
	}
}

func TestRouteGaps(t *testing.T) {
	got := mustScan(t, "testdata/express-login")

	for _, route := range got.Routes {
		if route.Registration.File == "dynamic.js" {
			t.Errorf("dynamic path produced a route: %+v", route)
		}
	}
	if !hasGap(got, "dynamic_path", "dynamic.js") {
		t.Fatalf("gaps = %+v, want dynamic_path in dynamic.js", got.Gaps)
	}

	var health *analysis.Route
	for i := range got.Routes {
		if got.Routes[i].PathPattern == "/health" {
			health = &got.Routes[i]
		}
	}
	if health == nil {
		t.Fatal("missing /health route")
	}
	if !hasGap(got, "unresolved_handler", "missing.js") {
		t.Fatalf("gaps = %+v, want unresolved_handler in missing.js", got.Gaps)
	}
	if !hasGap(got, "parse_error", "broken.js") {
		t.Fatalf("gaps = %+v, want parse_error in broken.js", got.Gaps)
	}
}

func TestTypeScriptRoutes(t *testing.T) {
	got := mustScan(t, "testdata/express-login")
	if countRoutes(got, "route.ts", "GET", "/ts") != 1 {
		t.Fatalf("routes = %+v, want one GET /ts", got.Routes)
	}
	if countRoutes(got, "route.tsx", "GET", "/tsx") != 1 {
		t.Fatalf("routes = %+v, want one GET /tsx", got.Routes)
	}
}

func TestRoutesDeterministic(t *testing.T) {
	first := mustJSON(t, mustScan(t, "testdata/express-login"))
	second := mustJSON(t, mustScan(t, "testdata/express-login"))
	if !bytes.Equal(first, second) {
		t.Fatal("two scans differed")
	}
	var got analysis.RouteInventory
	if err := json.Unmarshal(first, &got); err != nil {
		t.Fatal(err)
	}
	for _, route := range got.Routes {
		if route.PathPattern == "/hidden" || route.Registration.File == "node_modules/hidden.js" {
			t.Errorf("node_modules route present: %+v", route)
		}
	}
}

func mustScan(t *testing.T, root string) *analysis.RouteInventory {
	t.Helper()
	got, err := routeInventory(root)
	if err != nil {
		t.Fatalf("Routes: %v", err)
	}
	return got
}

func mustJSON(t *testing.T, g *analysis.RouteInventory) []byte {
	t.Helper()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(g); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func hasStep(route *analysis.Route, name string) bool {
	for _, step := range route.Steps {
		if step.Symbol.Name == name {
			return true
		}
	}
	return false
}

func hasCall(route *analysis.Route, name string) bool {
	for _, step := range route.Steps {
		if step.Kind == "call" && step.Symbol.Name == name {
			return true
		}
	}
	return false
}

func hasGap(g *analysis.RouteInventory, kind, file string) bool {
	for _, gap := range g.Gaps {
		if gap.Kind == kind && gap.At.File == file {
			return true
		}
	}
	return false
}

func findRoute(g *analysis.RouteInventory, file, method, path string) *analysis.Route {
	for i := range g.Routes {
		route := &g.Routes[i]
		if route.Registration.File == file && route.Method == method && route.PathPattern == path {
			return route
		}
	}
	return nil
}

func methodName(method string) string {
	return map[string]string{"GET": "get", "PUT": "put", "DELETE": "delete"}[method]
}

func countRoutes(g *analysis.RouteInventory, file, method, path string) int {
	n := 0
	for _, route := range g.Routes {
		if route.Registration.File == file && route.Method == method && route.PathPattern == path {
			n++
		}
	}
	return n
}
