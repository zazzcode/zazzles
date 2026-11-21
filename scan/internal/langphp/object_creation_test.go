package langphp

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
)

// An object creation without a class name is either an anonymous class, which
// is modeled as an unnamed project class, or a class chosen at run time,
// which resolves to nothing. Neither may stop the scan, and an anonymous
// class carries flow through its constructor, methods and parent exactly as
// the named class in the row before it does.
func TestObjectCreationWithoutClassName(t *testing.T) {
	for _, row := range []struct {
		name, source string
		xss          int
	}{
		{"named class method", `class R { function run($x) { echo $x; } } $a = new R; $a->run($_GET['x']);`, 1},
		{"anonymous class method", `$a = new class { function run($x) { echo $x; } }; $a->run($_GET['x']);`, 1},
		{"named constructor property", `class S { public $v; function __construct($v) { $this->v = $v; } function show() { echo $this->v; } } $a = new S($_GET['x']); $a->show();`, 1},
		{"anonymous constructor property", `$a = new class($_GET['x']) { public $v; function __construct($v) { $this->v = $v; } function show() { echo $this->v; } }; $a->show();`, 1},
		{"anonymous class inherits a method", `class Base { function run($x) { echo $x; } } $a = new class extends Base {}; $a->run($_GET['x']);`, 1},
		{"anonymous class from a function", `function make() { return new class { function go($x) { echo $x; } }; } make()->go($_GET['x']);`, 1},
		{"anonymous class inside an anonymous class", `$a = new class { function make() { return new class { function go($x) { echo $x; } }; } }; $a->make()->go($_GET['x']);`, 1},
		{"anonymous class with constant output", `$a = new class { function run() { echo 'ok'; } }; $a->run();`, 0},
		{"empty anonymous class", `$a = new class {};`, 0},
		{"anonymous class with a magic method", `$a = new class { function __wakeup() {} };`, 0},
		{"anonymous class implementing an interface", `interface I {} $a = new class implements I { function f() {} };`, 0},
		{"class named by a variable", `$n = 'Foo'; $a = new $n; echo $_GET['y'];`, 1},
		{"class named by a request value", `$n = $_GET['c']; $a = new $n($_GET['x']); echo $_GET['y'];`, 1},
		{"class named by an expression", `$a = new ($_GET['c'])(); echo $_GET['y'];`, 1},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php "+row.source), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			got := 0
			for _, u := range r.Uses {
				if u.Kind != "xss_candidate" {
					continue
				}
				got++
				if len(u.Dependencies) == 0 || u.Dependencies[0].Source.Kind != "input_source" {
					t.Errorf("candidate without a request source: %+v", u.Dependencies)
				}
			}
			if got != row.xss {
				t.Errorf("got %d xss candidates, want %d", got, row.xss)
			}
		})
	}
}

// An anonymous class cannot be named by serialized data, so it is not cited
// as a class a deserialized object can trigger.
func TestDeserializationPHPIgnoresAnonymousMagicClass(t *testing.T) {
	root := t.TempDir()
	source := `<?php $a = new class { function __wakeup() {} }; unserialize($_POST['x']);`
	if err := os.WriteFile(filepath.Join(root, "index.php"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, u := range r.Uses {
		if u.Kind != analysis.DeserializationKind {
			continue
		}
		found = true
		if cited := u.Completeness.Evidence["deserialization_magic_class"]; len(cited) != 0 {
			t.Errorf("anonymous class cited as a magic class: %+v", cited)
		}
	}
	if !found {
		t.Fatal("missing deserialization candidate")
	}
}
