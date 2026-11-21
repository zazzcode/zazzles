package langpy

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

func TestDeserializationPython(t *testing.T) {
	p := deserializationCase{contract: analysispacks.PythonPickle, capability: "code_execution", protection: "raw"}
	y := deserializationCase{contract: analysispacks.PythonYAML, capability: "code_execution", protection: "raw"}
	j := deserializationCase{contract: analysispacks.PythonJSONPickle, capability: "code_execution", protection: "raw"}
	r := deserializationCase{contract: analysispacks.PythonYAML, capability: "restricted_types", protection: "raw"}
	cases := map[string]deserializationCase{
		"PY-01":  p,
		"PY-02":  p,
		"PY-03":  p,
		"PY-04":  p,
		"PY-05":  p,
		"PY-06":  p,
		"PY-07a": p,
		"PY-07b": p,
		"PY-07c": p,
		"PY-07d": p,
		"PY-08a": p,
		"PY-08b": p,
		"PY-08c": p,
		"PY-I1":  p,
		"PY-09":  y,
		"PY-I2":  y,
		"PY-10":  y,
		"PY-11a": y,
		"PY-11b": y,
		"PY-13":  j,
		"PY-I3":  j,
		"PY-12":  r,
		"PY-U1":  {contract: analysispacks.PythonYAML, capability: "unresolved", protection: "raw", gap: "loader_unresolved"},
		"PY-V1":  {contract: analysispacks.PythonYAML, capability: "code_execution", protection: "raw", version: "3.13"},
		"PY-V2":  {contract: analysispacks.PythonYAML, capability: "restricted_types", protection: "raw", version: "5.4.1"},
		"PY-V4":  {contract: analysispacks.PythonYAML, capability: "unresolved", protection: "raw", gap: "version_unknown"},
		"PY-V5":  {contract: analysispacks.PythonYAML, capability: "unresolved", protection: "raw", gap: "version_unknown"},
		"PY-V6":  {contract: analysispacks.PythonYAML, capability: "code_execution", protection: "raw", version: "3.13"},
		"PY-C1":  {contract: analysispacks.PythonPickle, capability: "code_execution", protection: "guarded", control: "integrity_check"},
		"PY-C2":  {contract: analysispacks.PythonPickle, capability: "code_execution", protection: "guarded", control: "unkeyed_hash"},
		"PY-C3":  {contract: analysispacks.PythonPickle, capability: "code_execution", protection: "guarded", control: "class_allow_list"},
		"PY-C4":  {contract: analysispacks.PythonPickle, capability: "code_execution", protection: "guarded", control: "format_check"},
		"PY-N1":  {},
		"PY-N2":  {},
		"PY-N3":  {},
		"PY-N4":  {},
		"PY-N5":  {},
		"PY-V3":  {},
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
		if err != nil || entry.IsDir() || !slices.Contains([]string{".py"}, filepath.Ext(path)) {
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
			_, id, ok := strings.Cut(line, " # ")
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

			}
		})
	}
}

func TestDeserializationPythonTransfers(t *testing.T) {
	for _, transfer := range []string{
		"x.encode()", "x.decode()", "x.read()", "x.getvalue()", "bytes(x)", "str(x)",
		"io.BytesIO(x)", "io.StringIO(x)", "base64.b64decode(x)", "base64.urlsafe_b64decode(x)",
		"base64.b32decode(x)", "base64.b16decode(x)", "binascii.unhexlify(x)", "binascii.a2b_base64(x)",
		"bytes.fromhex(x)", "zlib.decompress(x)", "gzip.decompress(x)", "bz2.decompress(x)", "lzma.decompress(x)",
		"urllib.parse.unquote(x)", "urllib.parse.unquote_plus(x)", "urllib.parse.unquote_to_bytes(x)", "urllib.parse.parse_qs(x)", "urllib.parse.parse_qsl(x)",
	} {
		t.Run(transfer, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.py", `from flask import Flask, request
import base64, binascii, bz2, gzip, io, lzma, pickle, urllib.parse, zlib
app = Flask(__name__)
@app.post('/value')
def value():
    x = request.data
    return pickle.loads(`+transfer+`)
`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			got := usesOf(r, analysis.DeserializationKind, "")
			if len(got) != 1 {
				t.Fatalf("got %d candidates", len(got))
			}
			u := got[0]
			if len(u.Dependencies) != 1 || u.Dependencies[0].Source.Kind != "input_source" || len(u.Completeness.Blockers) > 0 || u.Deserialization.Paths[0].Protection != "raw" {
				t.Fatalf("lost data operand transfer: paths=%+v blockers=%+v", u.Deserialization.Paths, u.Completeness.Blockers)
			}
		})
	}
}

func TestDeserializationPythonSigningControls(t *testing.T) {
	for _, guard := range []string{
		"signing.loads(data)",
		"Signer(KEY).unsign(data)",
		"signer.unsign(data)",
	} {
		t.Run(guard, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.py", `from flask import Flask, request, abort
from django.core import signing
from itsdangerous import Signer
import pickle
KEY = "fixture-key"
app = Flask(__name__)
@app.post('/value')
def value():
    signer = Signer(KEY)
    data = request.data
    if not `+guard+`:
        abort(403)
    return pickle.loads(data)
`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			got := usesOf(r, analysis.DeserializationKind, "")
			if len(got) != 1 {
				t.Fatalf("got %d candidates", len(got))
			}
			facts := got[0].Deserialization
			if facts.Paths[0].Protection != "guarded" || !slices.ContainsFunc(facts.Controls, func(c analysis.DeserializationControl) bool {
				return c.Kind == analysis.DeserializationIntegrity
			}) {
				t.Fatalf("signing guard not recorded: %+v", facts)
			}
		})
	}
}

// Loader and version rows of D-3 beyond the fixture cases, including the
// version boundaries, and calls whose argument list carries a comment.
func TestDeserializationPythonOptions(t *testing.T) {
	const none = "none"
	for _, row := range []struct {
		name, pin, call, capability, gap string
	}{
		{"CSafeLoader", "", "yaml.load(x, Loader=yaml.CSafeLoader)", none, ""},
		{"BaseLoader", "", "yaml.load(x, yaml.BaseLoader)", none, ""},
		{"CBaseLoader", "", "yaml.load(x, Loader=yaml.CBaseLoader)", none, ""},
		{"CLoader", "", "yaml.load(x, Loader=yaml.CLoader)", "code_execution", ""},
		{"CUnsafeLoader", "", "yaml.load_all(x, Loader=yaml.CUnsafeLoader)", "code_execution", ""},
		{"FullLoader", "", "yaml.load(x, Loader=yaml.FullLoader)", "restricted_types", ""},
		{"CFullLoader", "", "yaml.load(x, yaml.CFullLoader)", "restricted_types", ""},
		{"unsafe_load_all", "", "yaml.unsafe_load_all(x)", "code_execution", ""},
		{"full_load_all", "", "yaml.full_load_all(x)", "restricted_types", ""},
		{"safe_load_all", "", "yaml.safe_load_all(x)", none, ""},
		{"project loader", "", "yaml.load(x, Loader=make_loader())", "unresolved", "loader_unresolved"},
		{"default at 5.0.2", "5.0.2", "yaml.load(x)", "code_execution", ""},
		{"default at 5.1", "5.1", "yaml.load(x)", "restricted_types", ""},
		{"default at 5.10", "5.10", "yaml.load_all(x)", "restricted_types", ""},
		{"default at 6.0", "6.0", "yaml.load(x)", none, ""},
		{"loader wins over version", "6.0", "yaml.load(x, Loader=yaml.UnsafeLoader)", "code_execution", ""},
		{"comment before the operand", "", "pickle.loads(  # decode the payload\n        x\n    )", "code_execution", ""},
		{"comment before a safe loader", "", "yaml.load(\n        x,  # stream\n        yaml.SafeLoader,\n    )", none, ""},
		{"comment in the constructor", "", "pickle.Unpickler(  # stream\n        io.BytesIO(x)\n    ).load()", "code_execution", ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			if row.pin != "" {
				writeSource(t, root, "requirements.txt", "PyYAML=="+row.pin)
			}
			writeSource(t, root, "app.py", `from flask import Flask, request
import io, pickle, yaml
app = Flask(__name__)
def make_loader():
    return yaml.SafeLoader
@app.post('/value')
def value():
    x = request.data
    return `+row.call+`
`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			got := usesOf(r, analysis.DeserializationKind, "")
			if row.capability == none {
				if len(got) != 0 {
					t.Fatalf("unexpected candidate: %+v", got[0].Deserialization)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d candidates", len(got))
			}
			if f := got[0].Deserialization; f.Capability != row.capability || f.OptionGap != row.gap || f.Version != row.pin && row.call == "yaml.load(x)" {
				t.Fatalf("incorrect facts: %+v", f)
			}
		})
	}
}

// Control rows of D-7 beyond the fixture cases: the first matching row wins.
func TestDeserializationPythonControlKinds(t *testing.T) {
	for _, row := range []struct{ guard, control string }{
		{"hmac.digest(KEY, data, 'sha256') != sig", "integrity_check"},
		{"not hmac.compare_digest(hashlib.sha256(data).hexdigest(), sig)", "integrity_check"},
		{"hashlib.md5(data).hexdigest() != sig", "unkeyed_hash"},
		{"len(data) > 4096", "format_check"},
	} {
		t.Run(row.guard, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.py", `from flask import Flask, request, abort
import hashlib, hmac, pickle
KEY = b"fixture-key"
app = Flask(__name__)
@app.post('/value')
def value():
    data = request.data
    sig = request.headers['X-Signature']
    if `+row.guard+`:
        abort(403)
    return pickle.loads(data)
`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			got := usesOf(r, analysis.DeserializationKind, "")
			if len(got) != 1 {
				t.Fatalf("got %d candidates", len(got))
			}
			f := got[0].Deserialization
			if f.Paths[0].Protection != "guarded" || len(f.Controls) != 1 || f.Controls[0].Kind != row.control {
				t.Fatalf("controls = %+v, paths = %+v, want one %s on a guarded path", f.Controls, f.Paths, row.control)
			}
		})
	}
}
