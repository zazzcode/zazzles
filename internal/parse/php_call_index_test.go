package parse

import (
	"strings"
	"testing"
)

func TestPHPProjectResolution(t *testing.T) {
	for _, tt := range []struct{ root, reference, kind, file string }{
		{"symfony-resolution", `App\Controller\Demo::show`, "container_service", "src/Controller/Demo.php"},
		{"symfony-resolution", "demo.controller", "container_service", "src/Controller/Demo.php"},
		{"symfony-resolution", "demo.alias::show", "container_service", "src/Controller/Demo.php"},
		{"symfony-resolution", `App\Controller\Demo`, "container_service", "src/Controller/Demo.php"},
		{"drupal-resolution", `Drupal\example\Greeter::greet`, "psr4", "src/Greeter.php"},
		{"drupal-resolution", "example.greeter::greet", "container_service", "src/Greeter.php"},
		{"symfony-resolution", "missing::show", "unresolved", ""},
		{"symfony-resolution", "demo.controller::missing", "unresolved", ""},
	} {
		t.Run(tt.root+"/"+tt.reference, func(t *testing.T) {
			s, err := newPHPSet("testdata/php/" + tt.root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			got := s.resolveReference(s.modules[s.files[0]], tt.reference)
			if got.Kind != tt.kind {
				t.Fatalf("got %+v", got)
			}
			if tt.file != "" {
				method := "__invoke"
				if strings.Contains(tt.reference, "::") {
					method = strings.Split(tt.reference, "::")[1]
				}
				if got.Target == nil || phpText(got.Target.module, phpField(got.Target.fn, "name")) != method {
					t.Fatalf("wrong method: %+v", got)
				}
				for _, span := range got.Inputs {
					if span.File == "composer.json" && span.EndByte == 0 {
						t.Fatal("composer provenance missing")
					}
				}

				if got.Target == nil || got.Target.module.file != tt.file || len(got.Inputs) < 2 {
					t.Fatalf("target/provenance: %+v", got)
				}
			} else if got.Target != nil || got.Reason == "" {
				t.Fatalf("unresolved: %+v", got)
			}
		})
	}
}
func TestPHPProjectResolutionBounds(t *testing.T) {
	for _, tt := range []struct{ name, composer, yaml, extra string }{
		{"unsafe", `{"autoload":{"psr-4":{"App\\":"../src/"}}}`, "", ""},
		{"flow", `{"autoload":{"psr-4":{"App\\":"src/"}}}`, "services:\n  x: {class: App\\C}\n", ""},
		{"anchor", `{"autoload":{"psr-4":{"App\\":"src/"}}}`, "services:\n  x:\n    class: &c App\\C\n", ""},
		{"alias cycle", `{"autoload":{"psr-4":{"App\\":"src/"}}}`, "services:\n  x:\n    alias: '@x'\n", ""},
		{"ambiguous", `{"autoload":{"psr-4":{"App\\":["src/","other/"]}}}`, "services:\n  x:\n    class: 'App\\C'\n", "<?php namespace App; class C {function __invoke(){}}"},
		{"wrong namespace", `{"autoload":{"psr-4":{"App\\":"src/"}}}`, "services:\n  x:\n    class: 'Other\\C'\n", ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			files := map[string]string{"composer.json": tt.composer, "services.yaml": tt.yaml, "src/C.php": "<?php namespace App; class C {function __invoke(){}}"}
			if tt.extra != "" {
				files["other/C.php"] = tt.extra
			}
			root := phpFixture(t, files)
			s, err := newPHPSet(root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			got := s.resolveReference(s.modules["src/C.php"], "x")
			if got.Kind != "unresolved" || got.Target != nil || got.Reason == "" {
				t.Fatalf("got %+v", got)
			}
		})
	}
}
func TestPHPLegacyResolutionParity(t *testing.T) {
	root := phpFixture(t, map[string]string{"a.php": "<?php function local_f(){}", "b.php": "<?php function remote_f(){}"})
	s, err := newPHPSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	m := s.modules["a.php"]
	for _, tt := range []struct{ name, kind string }{{"local_f", "direct"}, {"remote_f", "imported"}} {
		want := s.resolveFunction(m, tt.name)
		got := s.resolveReference(m, tt.name)
		if got.Kind != tt.kind || got.Target.module != want.module || got.Target.fn.Id() != want.fn.Id() {
			t.Fatalf("%s: %+v", tt.name, got)
		}
	}
}

func TestPHPAbsoluteServiceResource(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"composer.json":        "{\n\"autoload\":{\"psr-4\":{\"App\\\\\":\"config/src/\"}}\n}",
		"config/services.yaml": "services:\n  _defaults:\n    autowire: true\n  App\\:\n    resource: '/src'\n",
		"config/src/C.php":     "<?php namespace App; class C {function __invoke(){}}",
	})
	s, err := newPHPSet(root)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	r := s.resolveReference(s.modules["config/src/C.php"], "App\\C")
	if r.Kind != "unresolved" {
		t.Fatalf("absolute resource resolved: %+v", r)
	}
}
