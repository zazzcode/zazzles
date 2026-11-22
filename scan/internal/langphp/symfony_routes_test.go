package langphp

import (
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

func TestSymfonyRoutes(t *testing.T) {
	root := filepath.Join("testdata", "symfony", "routes")
	for _, tc := range []struct {
		id, fixture, name, mechanism, resolution, gap string
	}{
		{"RT-01", "routes", "GET /blog/{slug}", "attribute_route", "resolved", ""},
		{"RT-02/GET", "routes", "GET /a", "attribute_route", "resolved", ""},
		{"RT-02/POST", "routes", "POST /a", "attribute_route", "resolved", ""},
		{"RT-03", "routes", "ANY /b", "attribute_route", "resolved", ""},
		{"RT-04/first", "routes", "ANY /first", "attribute_route", "resolved", ""},
		{"RT-04/second", "routes", "ANY /second", "attribute_route", "resolved", ""},
		{"RT-05", "routes-annotation", "ANY /local/", "attribute_route", "resolved", ""},
		{"RT-06", "routes-annotation", "GET /blog/{slug}", "attribute_route", "resolved", ""},
		{"RT-07", "routes-annotation", "GET /c", "annotation_route", "resolved", ""},
		{"RT-08", "routes-yaml", "ANY /d", "config_route", "resolved", ""},
		{"RT-09", "routes-yaml", "ANY /missing", "config_route", "unresolved", "symfony_controller_unresolved"},
		{"RT-10", "routes", "ANY /unimported", "attribute_route", "unresolved", "symfony_route_not_imported"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			report, err := Analyze(filepath.Join(filepath.Dir(root), tc.fixture), "")
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range report.Entries {
				if entry.Name != tc.name {
					continue
				}
				if entry.HTTP == nil || entry.HTTP.Framework != "symfony" {
					t.Fatalf("wrong HTTP metadata: %+v", entry.HTTP)
				}
				if tc.id == "RT-03" && entry.HTTP.Method != "" {
					t.Fatalf("ANY route has method %q", entry.HTTP.Method)
				}
				for _, binding := range report.DispatchBindings {
					if binding.EntryID != entry.ID {
						continue
					}
					if binding.Mechanism != tc.mechanism || binding.Resolution != tc.resolution {
						t.Fatalf("unexpected dispatch: %+v", binding)
					}
					if tc.gap != "" {
						for _, gap := range binding.Gaps {
							if gap.Kind == tc.gap {
								return
							}
						}
						t.Fatalf("missing dispatch gap %s", tc.gap)
					}
					if binding.CallableID == "" {
						t.Fatal("resolved dispatch has no callable")
					}
					if tc.id == "RT-01" {
						for _, callable := range report.Callables {
							if callable.ID == binding.CallableID && callable.Name == `App\Controller\BlogController::show` && callable.Language == "php" {
								return
							}
						}
						t.Fatal("RT-01 dispatch does not point to the PHP action")
					}
					return
				}
				t.Fatal("missing dispatch")
			}
			t.Fatalf("missing entry %s", tc.name)
		})
	}
	t.Run("RT-11", func(t *testing.T) {
		report, err := Analyze(root, "")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range report.Entries {
			if entry.HTTP != nil && entry.HTTP.Framework == "symfony" && entry.HTTP.Path == "" &&
				hasSymfonyGap(entry.Gaps, "symfony_route_dynamic") {
				return
			}
		}
		t.Fatal("dynamic route did not retain its gap")
	})
	t.Run("RT-12", func(t *testing.T) {
		report, err := Analyze(filepath.Join(filepath.Dir(root), "mixed"), "")
		if err != nil {
			t.Fatal(err)
		}
		names := map[string]bool{}
		for _, entry := range report.Entries {
			names[entry.Name] = true
		}
		if len(names) != 3 || !names["FILE /legacy/page.php"] || !names["FILE /app/public/index.php"] || !names["ANY /mixed"] {
			t.Fatalf("entries: %v", names)
		}
	})
	t.Run("RT-13", func(t *testing.T) {
		inv, err := testInventory(root)
		if err != nil {
			t.Fatal(err)
		}
		routes, _, err := Routes(inv)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, route := range routes {
			found = found || route.Framework == "symfony" && route.Method == "GET" && route.PathPattern == "/blog/{slug}"
			if route.Framework == "php" && route.PathPattern == "/src/Controller/BlogController.php" {
				t.Fatal("controller is a FILE route")
			}
		}
		if !found {
			t.Fatal("missing route in route inventory")
		}
	})
	t.Run("RT-14", func(t *testing.T) {
		report, err := Analyze(root, "src/Controller/BlogController.php")
		if err != nil {
			t.Fatal(err)
		}
		if len(report.Entries) != 1 || report.Entries[0].Name != "GET /blog/{slug}" {
			t.Fatalf("filtered entries: %+v", report.Entries)
		}
	})
}

func hasSymfonyGap(gaps []analysis.Gap, kind string) bool {
	for _, gap := range gaps {
		if gap.Kind == kind {
			return true
		}
	}
	return false
}
