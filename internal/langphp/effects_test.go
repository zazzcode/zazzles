package langphp

import (
	"strings"
	"testing"
)

func TestPHPBuiltinContentEffects(t *testing.T) {
	for _, name := range []string{"array_shift", "json_decode", "base64_decode", "base64_encode", "strrpos", "addslashes"} {
		t.Run(name, func(t *testing.T) {
			argument := "$_GET['x']"
			if name == "array_shift" {
				argument = "$items"
			}
			if name == "strrpos" {
				argument += ", '.'"
			}
			source := "<?php $items = [$_GET['x']]; echo " + name + "(" + argument + ");"
			r := phpAnalyze(t, phpFixture(t, map[string]string{"index.php": source}), "")
			if len(r.Uses) == 0 {
				t.Fatal("request content disappeared")
			}
			found := false
			for _, u := range r.Uses {
				for _, g := range u.Gaps {
					if g.Kind == "php_call_unresolved" && strings.Contains(g.Detail, name) {
						t.Fatalf("effect not applied: %v", g)
					}
				}
				if len(u.Dependencies) > 0 {
					found = true
					if u.XSS != nil && u.XSS.Protection != "unknown" {
						t.Fatalf("content transform became protection: %+v", u.XSS)
					}
				}
			}
			if !found {
				t.Fatal("dependencies disappeared")
			}
		})
	}
}
func TestPHPBuiltinContentEffectShadowing(t *testing.T) {
	for _, source := range []string{
		"<?php function base64_decode($x){return external($x);} echo base64_decode($_GET['x']);",
		"<?php namespace App; function base64_decode($x){return external($x);} echo base64_decode($_GET['x']);",
		"<?php use function App\\other as base64_decode; echo base64_decode($_GET['x']);",
		"<?php $fn = 'base64_decode'; echo $fn($_GET['x']);",
	} {
		t.Run(source, func(t *testing.T) {
			root := phpFixture(t, map[string]string{"index.php": source})
			s, err := newPHPSet(root)
			if err != nil {
				t.Fatal(err)
			}
			defer s.close()
			f := &phpFlow{set: s, module: s.modules["index.php"]}
			if strings.Contains(source, "$fn") {
				if f.phpBuiltinEffectName("$fn") {
					t.Fatal("dynamic name")
				}
			} else if f.phpBuiltinEffectName("base64_decode") {
				t.Fatal("shadowed builtin")
			}
		})
	}
}

func TestPHPArrayShiftInvalidatesShape(t *testing.T) {
	root := phpFixture(t, map[string]string{"index.php": "<?php $a=['0'=>htmlspecialchars($_GET['safe']),'1'=>$_GET['raw']]; $v=array_shift($a); echo $a['0']; echo $v['0'];"})
	r := phpAnalyze(t, root, "")
	count := 0
	for _, u := range r.Uses {
		if u.XSS != nil {
			count++
			if u.XSS.Protection != "unknown" {
				t.Fatalf("stale protection after reindex: %+v", u.XSS)
			}
		}
	}
	if count != 2 {
		t.Fatalf("got %d render uses", count)
	}
}

func TestPHPBuiltinEffectsIgnoreUnrelatedNamespaces(t *testing.T) {
	root := phpFixture(t, map[string]string{
		"index.php": "<?php echo base64_decode($_GET['x']);",
		"api.php":   "<?php namespace App; class Controller {}",
	})
	r := phpAnalyze(t, root, "")
	found := false
	for _, u := range r.Uses {
		if u.Sink.Span.File == "index.php" {
			found = true
			for _, g := range u.Gaps {
				if g.Kind == "php_call_unresolved" {
					t.Fatal("unrelated namespace blocked builtin", g)
				}
			}
		}
	}
	if !found {
		t.Fatal("missing content candidate")
	}
}
