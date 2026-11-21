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
		{"constant options", `const OPTIONS = ['allowed_classes' => false]; unserialize($_POST['x'], OPTIONS);`, false},
		{"named options before data", `unserialize(options: ['allowed_classes' => false], data: $_POST['x']);`, false},
		{"named unsafe data", `unserialize(options: ['allowed_classes' => true], data: $_POST['x']);`, true},
		{"changed options", `$o = ['allowed_classes' => false]; $o['allowed_classes'] = true; unserialize($_POST['x'], $o);`, true},
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
