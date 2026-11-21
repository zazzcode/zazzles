package langphp

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

type deserializationCase struct {
	contract, capability, protection, gap, version, control string
}

func TestDeserializationPHP(t *testing.T) {
	p := deserializationCase{contract: analysispacks.PHPUnserialize, capability: "object_injection", protection: "raw"}
	y := deserializationCase{contract: analysispacks.PHPSymfonyYAML, capability: "object_injection", protection: "raw"}
	cases := map[string]deserializationCase{
		"PHP-01": p,
		"PHP-02": p,
		"PHP-03": p,
		"PHP-04": p,
		"PHP-05": p,
		"PHP-06": p,
		"PHP-07": p,
		"PHP-E1": p,
		"PHP-08": y,
		"PHP-09": y,
		"PHP-U1": {contract: analysispacks.PHPSymfonyYAML, capability: "unresolved", protection: "raw", gap: "loader_unresolved"},
		"PHP-C1": {contract: analysispacks.PHPUnserialize, capability: "object_injection", protection: "guarded", control: "integrity_check"},
		"PHP-C2": {contract: analysispacks.PHPUnserialize, capability: "object_injection", protection: "guarded", control: "integrity_check"},
		"PHP-C3": {contract: analysispacks.PHPUnserialize, capability: "object_injection", protection: "guarded", control: "unkeyed_hash"},
		"PHP-C4": {contract: analysispacks.PHPUnserialize, capability: "object_injection", protection: "guarded", control: "class_allow_list"},
		"PHP-N1": {},
		"PHP-N2": {},
		"PHP-N3": {},
		"PHP-N4": {},
		"PHP-N5": {},
		"PHP-N6": {},
		"PHP-N7": {},
		"PHP-N8": {},
	}
	checkDeserializationCases(t, "testdata/deserialization", cases)
}

func checkDeserializationCases(t *testing.T, root string, cases map[string]deserializationCase) {
	t.Helper()
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	type location struct {
		file string
		line int
	}
	anchors := map[location]string{}
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !slices.Contains([]string{".php"}, filepath.Ext(path)) {
			return err
		}
		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		for i, line := range strings.Split(string(source), "\n") {
			_, id, ok := strings.Cut(line, " // ")
			if ok {
				id = strings.TrimSpace(id)
				if _, exists := cases[id]; exists {
					anchors[location{filepath.ToSlash(rel), i + 1}] = id
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(anchors) != len(cases) {
		t.Fatalf("found %d fixture markers for %d cases", len(anchors), len(cases))
	}
	byCase := map[string][]analysis.CandidateUse{}
	for _, u := range report.Uses {
		if u.Kind != analysis.DeserializationKind {
			continue
		}
		at := location{u.Sink.Span.File, u.Sink.Span.StartLine}
		if id := anchors[at]; id != "" {
			byCase[id] = append(byCase[id], u)
		} else {
			t.Errorf("unexpected candidate at %v: %s", at, u.Sink.Text)
		}
	}
	for id, row := range cases {
		t.Run(id, func(t *testing.T) {
			uses := byCase[id]
			if row.contract == "" {
				if len(uses) > 0 {
					t.Fatalf("unexpected candidate: %+v", uses[0].Deserialization)
				}
				return
			}
			if len(uses) == 0 {
				t.Fatal("missing candidate")
			}
			for _, u := range uses {
				f, c := u.Deserialization, u.Completeness
				if f == nil || f.ContractID != row.contract || f.Capability != row.capability ||
					f.OptionGap != row.gap || f.Version != row.version || u.APIModel == nil || u.APIModel.ID != row.contract {
					t.Fatalf("incorrect facts: %+v", f)
				}
				if err := f.Validate(len(u.Dependencies), len(u.Context)); err != nil {
					t.Fatal(err)
				}
				if c == nil {
					t.Fatal("missing completeness")
				}
				if c.ClaimKind != "deserialization" || len(c.Blockers) != 0 {
					t.Fatalf("unexpected completeness: %+v, gaps: %+v", c.Blockers, u.Gaps)
				}
				for _, role := range c.Required {
					if len(c.Evidence[role]) == 0 {
						t.Errorf("missing role %s", role)
					}
				}
				for _, p := range f.Paths {
					if p.Protection != row.protection || u.Dependencies[p.Dependency].Source.Kind != "input_source" {
						t.Errorf("unexpected source path: %+v", p)
					}
				}
				if row.control != "" && !slices.ContainsFunc(f.Controls, func(c analysis.DeserializationControl) bool { return c.Kind == row.control }) {
					t.Errorf("missing %s in %+v", row.control, f.Controls)
				}
				if id == "PHP-E1" {
					items := c.Evidence["deserialization_magic_class"]
					if len(items) != 2 || items[0].Text != "Logger" || items[1].Text != "Token" {
						t.Errorf("unexpected magic-method classes: %+v", items)
					}
				}
			}
		})
	}
}

func TestDeserializationPHPTransfers(t *testing.T) {
	for _, transfer := range []string{
		"base64_decode($x)", "urldecode($x)", "rawurldecode($x)", "hex2bin($x)", "gzuncompress($x)",
		"gzinflate($x)", "gzdecode($x)", "stripslashes($x)", "trim($x)", "(string) $x",
	} {
		t.Run(transfer, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php\n$x = $_COOKIE['p'];\nunserialize("+transfer+");\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(r.Uses, func(u analysis.CandidateUse) bool { return u.Kind == analysis.DeserializationKind })
			if i == -1 {
				t.Fatal("missing candidate")
			}
			u := r.Uses[i]
			if len(u.Dependencies) != 1 || u.Dependencies[0].Source.Kind != "input_source" || len(u.Completeness.Blockers) > 0 || u.Deserialization.Paths[0].Protection != "raw" {
				t.Fatalf("lost data operand transfer: paths=%+v blockers=%+v", u.Deserialization.Paths, u.Completeness.Blockers)
			}
		})
	}
}

func TestDeserializationPHPBinding(t *testing.T) {
	for _, row := range []struct {
		name, source string
		candidate    bool
	}{
		{"namespaced global fallback", `namespace App; unserialize($_POST['x']);`, true},
		{"namespaced override", `namespace App; function unserialize($x) { return $x; } unserialize($_POST['x']);`, false},
		{"function import", `namespace App; use function App\Reader\parse as unserialize; unserialize($_POST['x']);`, false},
		{"group function import", `namespace App; use App\Reader\{function parse as unserialize}; unserialize($_POST['x']);`, false},
		{"qualified builtin overrides import", `namespace App; use function App\Reader\parse as unserialize; \unserialize($_POST['x']);`, true},
		{"fully qualified Yaml", `\Symfony\Component\Yaml\Yaml::parse($_POST['y'], \Symfony\Component\Yaml\Yaml::PARSE_OBJECT);`, true},
		{"static method named unserialize", `Store::unserialize($_POST['x']);`, false},
		{"constant options", `const OPTIONS = ['allowed_classes' => false]; unserialize($_POST['x'], OPTIONS);`, false},
		{"named options before data", `unserialize(options: ['allowed_classes' => false], data: $_POST['x']);`, false},
		{"named unsafe data", `unserialize(options: ['allowed_classes' => true], data: $_POST['x']);`, true},
		{"changed options", `$o = ['allowed_classes' => false]; $o['allowed_classes'] = true; unserialize($_POST['x'], $o);`, true},
		{"options rebound by foreach", `$o = ['allowed_classes' => false]; foreach ($_GET['all'] as $o) {} unserialize($_POST['x'], $o);`, true},
		{"options passed by reference", `function tweak(&$v) { $v['allowed_classes'] = true; } $o = ['allowed_classes' => false]; tweak($o); unserialize($_POST['x'], $o);`, true},
		{"options aliased by reference", `$o = ['allowed_classes' => false]; $r = &$o; $r['allowed_classes'] = true; unserialize($_POST['x'], $o);`, true},
		{"options rebound by destructuring", `$o = ['allowed_classes' => false]; [$o, $z] = [$_GET['o'], 1]; unserialize($_POST['x'], $o);`, true},
		{"options written by output argument", `$o = ['allowed_classes' => false]; preg_match('/(.*)/', $_GET['o'], $o); unserialize($_POST['x'], $o);`, true},
		{"options written by extract", `$o = ['allowed_classes' => false]; extract($_GET); unserialize($_POST['x'], $o);`, true},
		{"options captured by reference", `$o = ['allowed_classes' => false]; $f = function () use (&$o) { $o = []; }; $f(); unserialize($_POST['x'], $o);`, true},
		{"options global written elsewhere", `$o = ['allowed_classes' => false]; function widen() { global $o; $o = []; } widen(); unserialize($_POST['x'], $o);`, true},
		{"unrelated local of the same name", `$o = ['allowed_classes' => false]; function other($o) { return $o; } unserialize($_POST['x'], $o);`, false},
		{"literal flags without object support", `use Symfony\Component\Yaml\Yaml; Yaml::parse($_POST['y'], Yaml::PARSE_CONSTANT | Yaml::PARSE_DATETIME);`, false},
		{"conditional initialization", `if ($_POST['flag']) { $o = ['allowed_classes' => false]; } unserialize($_POST['x'], $o);`, true},
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
			got := slices.ContainsFunc(r.Uses, func(u analysis.CandidateUse) bool { return u.Kind == analysis.DeserializationKind })
			if got != row.candidate {
				t.Errorf("candidate = %v, want %v", got, row.candidate)
			}
		})
	}
}

// Guard rows of D-7: presence and request-method tests are not guards, a
// rejecting branch may throw or run statements before it leaves, and a guard
// on a value survives decoding that value into another variable.
func TestDeserializationPHPGuards(t *testing.T) {
	const reject = `if (!hash_equals(hash_hmac('sha256', $d, KEY), $sig)) `
	for _, row := range []struct {
		name, source, protection, control string
	}{
		{"isset", `if (isset($_COOKIE['p'])) { unserialize($_COOKIE['p']); }`, "raw", ""},
		{"empty reject", `$d = $_POST['d']; if (empty($d)) { exit; } unserialize($d);`, "raw", ""},
		{"truthiness reject", `$d = $_POST['d']; if (!$d) { exit; } unserialize($d);`, "raw", ""},
		{"null comparison", `$d = $_POST['d']; if ($d !== null && $d !== '') { unserialize($d); }`, "raw", ""},
		{"request method and presence", `if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['d'])) { unserialize(base64_decode($_POST['d'])); }`, "raw", ""},
		{"throwing reject", `$d = $_POST['d']; $sig = $_GET['s']; ` + reject + `{ throw new RuntimeException('bad'); } unserialize($d);`, "guarded", "integrity_check"},
		{"multi-statement reject", `$d = $_POST['d']; $sig = $_GET['s']; ` + reject + `{ http_response_code(403); exit; } unserialize($d);`, "guarded", "integrity_check"},
		{"non-terminating branch", `$d = $_POST['d']; $sig = $_GET['s']; ` + reject + `{ error_log('bad'); } unserialize($d);`, "raw", ""},
		{"verify then decode", `$raw = $_COOKIE['p']; $sig = $_GET['s']; if (!hash_equals(hash_hmac('sha256', $raw, KEY), $sig)) { exit; } $d = base64_decode($raw); unserialize($d);`, "guarded", "integrity_check"},
		{"operand replaced after the check", `$d = $_COOKIE['p']; $sig = $_GET['s']; ` + reject + `{ exit; } $d = $_POST['other']; unserialize($d);`, "raw", ""},
		{"sodium verification", `$d = $_POST['d']; if (!sodium_crypto_auth_verify($_GET['s'], $d, KEY)) { exit; } unserialize($d);`, "guarded", "integrity_check"},
		{"sha1", `$d = $_POST['d']; if (sha1($d) !== $_GET['s']) { exit; } unserialize($d);`, "guarded", "unkeyed_hash"},
		{"hash", `$d = $_POST['d']; if (hash('sha256', $d) !== $_GET['s']) { exit; } unserialize($d);`, "guarded", "unkeyed_hash"},
		{"crc32", `$d = $_POST['d']; if (crc32($d) != $_GET['s']) { exit; } unserialize($d);`, "guarded", "unkeyed_hash"},
		{"format check", `$d = $_POST['d']; if (!preg_match('/^a:/', $d)) { exit; } unserialize($d);`, "guarded", "format_check"},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "index.php"), []byte("<?php const KEY = 'fixture-key'; "+row.source), 0o600); err != nil {
				t.Fatal(err)
			}
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(r.Uses, func(u analysis.CandidateUse) bool { return u.Kind == analysis.DeserializationKind })
			if i == -1 {
				t.Fatal("missing candidate")
			}
			f := r.Uses[i].Deserialization
			for _, p := range f.Paths {
				if p.Protection != row.protection {
					t.Errorf("protection = %s, want %s (controls %+v)", p.Protection, row.protection, f.Controls)
				}
			}
			if row.control == "" && len(f.Controls) > 0 || row.control != "" && (len(f.Controls) != 1 || f.Controls[0].Kind != row.control) {
				t.Errorf("controls = %+v, want %q", f.Controls, row.control)
			}
		})
	}
}

// A declaration or import in another file of the project decides the binding
// of an unqualified name, per namespace.
func TestDeserializationPHPBindingAcrossFiles(t *testing.T) {
	root := t.TempDir()
	for name, source := range map[string]string{
		"lib.php":    `namespace App; function unserialize($x) { return $x; } function helper() { return 1; }`,
		"shadow.php": `namespace App; unserialize($_POST['x']);`,
		"global.php": `function decode($x) { return $x; } unserialize(base64_decode($_POST['x']));`,
		"other.php":  `namespace Other; unserialize($_POST['x']);`,
		"import.php": `namespace Other; use function App\helper as unserialize; unserialize($_POST['x']);`,
		"rooted.php": `namespace App; \unserialize($_POST['x']);`,
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte("<?php "+source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, u := range r.Uses {
		if u.Kind == analysis.DeserializationKind {
			got = append(got, u.Sink.Span.File)
		}
	}
	slices.Sort(got)
	if want := []string{"global.php", "other.php", "rooted.php"}; !slices.Equal(slices.Compact(got), want) {
		t.Errorf("candidates in %v, want %v", got, want)
	}
}

// D-11: every listed magic method and Serializable qualifies; the evidence is
// ordered by file then position and capped at 20.
func TestDeserializationPHPMagicClasses(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, name), []byte("<?php\n"+source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var hooks strings.Builder
	want := []string{}
	for i, method := range []string{"__wakeup", "__unserialize", "__destruct", "__toString", "__call", "__get", "__set", "__invoke"} {
		name := "Hook" + string(rune('A'+i))
		hooks.WriteString("class " + name + " { function " + method + "() {} }\n")
		want = append(want, name)
	}
	hooks.WriteString("class Stored implements Serializable { function serialize() {} function unserialize($d) {} }\nclass Plain { function run() {} }\n")
	want = append(want, "Stored")
	write("a_hooks.php", hooks.String())
	var many strings.Builder
	for i := 0; i < 15; i++ {
		name := "Late" + string(rune('A'+i))
		many.WriteString("class " + name + " { function __destruct() {} }\n")
		want = append(want, name)
	}
	write("b_many.php", many.String())
	write("index.php", `unserialize($_POST['x']);`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(r.Uses, func(u analysis.CandidateUse) bool { return u.Kind == analysis.DeserializationKind })
	if i == -1 {
		t.Fatal("missing candidate")
	}
	var got []string
	for _, e := range r.Uses[i].Completeness.Evidence["deserialization_magic_class"] {
		got = append(got, e.Text)
	}
	if !slices.Equal(got, want[:20]) {
		t.Errorf("magic classes = %v, want %v", got, want[:20])
	}
}
