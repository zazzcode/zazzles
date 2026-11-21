package langjs

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

func TestDeserializationJS(t *testing.T) {
	n := deserializationCase{contract: analysispacks.NodeSerialize, capability: "code_execution", protection: "raw"}
	cases := map[string]deserializationCase{
		"JS-01": n,
		"JS-02": n,
		"JS-03": n,
		"JS-07": n,
		"JS-04": {contract: analysispacks.JSYAML, capability: "code_execution", protection: "raw", version: "3.14.1"},
		"JS-05": {contract: analysispacks.JSYAML, capability: "code_execution", protection: "raw", version: "3.14.1"},
		"JS-06": {contract: analysispacks.JSYAML, capability: "code_execution", protection: "raw", version: "3.14.1"},
		"JS-I1": {contract: analysispacks.JSYAML, capability: "code_execution", protection: "raw", version: "3.14.1"},
		"JS-U1": {contract: analysispacks.JSYAML, capability: "unresolved", protection: "raw", gap: "version_unknown"},
		"JS-U2": {contract: analysispacks.JSYAML, capability: "unresolved", protection: "raw", gap: "loader_unresolved", version: "3.14.1"},
		"JS-U3": {contract: analysispacks.JSYAML, capability: "unresolved", protection: "raw", gap: "version_unknown"},
		"JS-C1": {contract: analysispacks.NodeSerialize, capability: "code_execution", protection: "guarded", control: "integrity_check"},
		"JS-C2": {contract: analysispacks.NodeSerialize, capability: "code_execution", protection: "guarded", control: "unkeyed_hash"},
		"JS-N1": {},
		"JS-N2": {},
		"JS-N3": {},
		"JS-N4": {},
		"JS-N5": {},
		"JS-N6": {},
	}
	for _, variant := range []string{"js", "ts"} {
		t.Run(variant, func(t *testing.T) {
			checkDeserializationCases(t, filepath.Join("testdata/deserialization", variant), cases)
		})
	}
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
		if err != nil || entry.IsDir() || !slices.Contains([]string{".js", ".ts"}, filepath.Ext(path)) {
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

			}
		})
	}
}

func TestDeserializationJSBrowser(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "package.json", `{"dependencies":{"next":"15.0.0","js-yaml":"3.14.1"}}`)
	writeSource(t, root, "app/client/page.tsx", `"use client";
import yaml from 'js-yaml';
import { useSearchParams } from 'next/navigation';
export default function Page() {
  const value = useSearchParams().get('value');
  yaml.load(value);
  document.write(value);
  return null;
}
`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	var browserWitness bool
	for _, u := range r.Uses {
		if u.Kind == analysis.DeserializationKind {
			t.Errorf("browser deserialization candidate: %+v", u.Sink)
		}
		browserWitness = browserWitness || u.Kind == "xss_candidate" && u.EntryKind == "browser"
	}
	if !browserWitness {
		t.Error("fixture did not enter browser analysis")
	}
}

func TestDeserializationJSTransfers(t *testing.T) {
	for _, transfer := range []string{
		"Buffer.from(x)", "Buffer.from(x, 'base64').toString()", "x.toString()", "String(x)", "atob(x)",
		"decodeURIComponent(x)", "decodeURI(x)", "unescape(x)", "zlib.inflateSync(x)", "zlib.gunzipSync(x)",
		"zlib.unzipSync(x)", "zlib.brotliDecompressSync(x)", "(x as string)",
	} {
		t.Run(transfer, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.ts", `import express from 'express';
import serialize from 'node-serialize';
import zlib from 'node:zlib';
const app = express();
app.post('/value', (req, res) => {
  const x = req.body.x;
  serialize.unserialize(`+transfer+`);
  res.end();
});
`)
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

// Exercise Next.js entry acquisition by parsing source fixtures only.
func TestDeserializationNextJS(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "package.json", `{"dependencies":{"next":"15.0.0","js-yaml":"3.14.1"}}`)
	for _, row := range []struct{ file, operand string }{
		{"profile.js", "req.cookies.profile"},
		{"config.js", "req.body.yaml"},
	} {
		for _, operation := range []string{"load", "safeLoad"} {
			writeSource(t, root, "pages/api/"+operation+"/"+row.file, `import yaml from 'js-yaml';
export default function handler(req, res) {
  yaml.`+operation+`(`+row.operand+`);
  res.end();
}
`)
		}
	}
	report, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, u := range report.Uses {
		if u.Kind != analysis.DeserializationKind {
			continue
		}
		count++
		if u.EntryKind != "http" || u.Deserialization.ContractID != analysispacks.JSYAML ||
			len(u.Completeness.Blockers) != 0 || !strings.HasPrefix(u.Sink.Text, "yaml.load(") ||
			len(u.Deserialization.Paths) != 1 || u.Deserialization.Paths[0].Protection != "raw" {
			t.Errorf("wrong deserialization evidence at %v: %+v (%+v)", u.Sink.Span, u.Deserialization, u.Completeness.Blockers)
		}
	}
	if count != 2 {
		t.Errorf("got %d deserialization candidates, want 2", count)
	}
}

// Schema and version rows of D-5 beyond the paired fixture cases, including
// the 4.0.0 boundary, and calls whose argument list carries a comment.
func TestDeserializationJSOptions(t *testing.T) {
	const none = "none"
	for _, row := range []struct {
		name, version, call, capability, gap string
	}{
		{"legacy default below the boundary", "3.99.99", "yaml.load(x)", "code_execution", ""},
		{"default at the boundary", "4.0.0", "yaml.load(x)", none, ""},
		{"safe schema on 3", "3.14.1", "yaml.load(x, { schema: yaml.DEFAULT_SAFE_SCHEMA })", none, ""},
		{"core schema on 3", "3.14.1", "yaml.loadAll(x, { schema: yaml.CORE_SCHEMA })", none, ""},
		{"failsafe schema on 4", "4.1.0", "yaml.load(x, { schema: yaml.FAILSAFE_SCHEMA })", none, ""},
		{"default schema on 4", "4.1.0", "yaml.load(x, { schema: yaml.DEFAULT_SCHEMA })", none, ""},
		{"default schema on 3", "3.14.1", "yaml.load(x, { schema: yaml.DEFAULT_SCHEMA })", "unresolved", "loader_unresolved"},
		{"full schema on 4", "4.1.0", "yaml.load(x, { schema: yaml.DEFAULT_FULL_SCHEMA })", "unresolved", "loader_unresolved"},
		{"full schema overrides safeLoadAll", "3.14.1", "yaml.safeLoadAll(x, { schema: yaml.DEFAULT_FULL_SCHEMA })", "code_execution", ""},
		{"loadAll iterator before options", "3.14.1", "yaml.loadAll(x, () => {}, { schema: yaml.JSON_SCHEMA })", none, ""},
		{"opaque options on load", "3.14.1", "yaml.load(x, opts)", "unresolved", "loader_unresolved"},
		{"opaque options on safeLoad", "3.14.1", "yaml.safeLoad(x, opts)", "unresolved", "loader_unresolved"},
		{"safeLoad with other options", "3.14.1", "yaml.safeLoad(x, { filename: 'body.yml' })", none, ""},
		{"comment before the operand", "3.14.1", "serialize.unserialize(/* payload */ x)", "code_execution", ""},
		{"comment after the operand", "4.1.0", "yaml.load(x /* trusted? */)", none, ""},
		{"comment before a safe schema", "3.14.1", "yaml.load(x /* body */, { schema: yaml.JSON_SCHEMA })", none, ""},
	} {
		t.Run(row.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "package.json", `{"dependencies":{"js-yaml":"`+row.version+`"}}`)
			writeSource(t, root, "app.js", `const express = require('express');
const yaml = require('js-yaml');
const serialize = require('node-serialize');
const app = express();
const opts = { schema: yaml.DEFAULT_FULL_SCHEMA };
app.post('/value', (req, res) => {
  const x = req.body.x;
  res.json(`+row.call+`);
});
`)
			r, err := Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			var got []analysis.CandidateUse
			for _, u := range r.Uses {
				if u.Kind == analysis.DeserializationKind {
					got = append(got, u)
				}
			}
			if row.capability == none {
				if len(got) != 0 {
					t.Fatalf("unexpected candidate: %+v", got[0].Deserialization)
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("got %d candidates", len(got))
			}
			f := got[0].Deserialization
			if f.Capability != row.capability || f.OptionGap != row.gap {
				t.Fatalf("incorrect facts: %+v", f)
			}
			if operand := got[0].Completeness.Evidence["deserialization_operand"]; len(operand) != 1 || operand[0].Text != "x" {
				t.Errorf("operand evidence = %+v, want x", operand)
			}
		})
	}
}
