package langphp

import (
	"testing"
)

func TestPHPServiceTargetRegressions(t *testing.T) {
	for _, tt := range []struct{ name, yaml, source string }{
		{"class_and_alias", "services:\n  x:\n    class: 'App\\C'\n    alias: 'y'\n  y:\n    class: 'App\\C'\n", "<?php namespace App; class C {public function __invoke(){}}"},
		{"private_method", "services:\n  x:\n    class: 'App\\C'\n", "<?php namespace App; class C {private function __invoke(){}}"},
		{"abstract_method", "services:\n  x:\n    class: 'App\\C'\n", "<?php namespace App; abstract class C {abstract public function __invoke();}"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			s, e := newPHPSet(phpFixture(t, map[string]string{"composer.json": `{"autoload":{"psr-4":{"App\\":"src/"}}}`, "services.yaml": tt.yaml, "src/C.php": tt.source}))
			if e != nil {
				t.Fatal(e)
			}
			defer s.close()
			r := s.resolveReference(s.modules["src/C.php"], "x")
			t.Logf("kind=%s reason=%s", r.Kind, r.Reason)
			if r.Kind != "unresolved" {
				t.Error("invalid target/config resolved")
			}
		})
	}
}
