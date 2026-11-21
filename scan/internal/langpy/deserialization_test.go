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
