package parse

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNodeDiscoveryProvenance(t *testing.T) {
	root := t.TempDir()
	source := `const express=require('express');const app=express();function handler(req,res){res.send('ok')};app.get('/known',handler);function exposeHTTP(path,handler){if(enabled)app.get(path,handler)};exposeHTTP('/unknown',handler);`
	writeSource(t, root, "server.js", source)
	r, err := AnalyzeWithOptions(root, "", nil, Options{DiscoverRoutes: true})
	if err != nil {
		t.Fatal(err)
	}
	ps := r.Discovery
	known, provisional := 0, 0
	for _, p := range ps {
		p.ModelChoice = "route"
		v := VerifyDiscovery(root, p, r)
		if strings.HasPrefix(p.Registration.Text, "app.get") {
			if v.State != "verified_existing" {
				t.Fatalf("known binding not verified: %+v", v)
			}
			known++
		} else if strings.HasPrefix(p.Registration.Text, "exposeHTTP") {
			if v.State != "provisional" || v.VerifiedEntryID != "" {
				t.Fatal("model proposal acquired trusted dispatch")
			}
			if len(v.Context) == 0 {
				t.Fatal("source-present wrapper implementation omitted")
			}
			provisional++
		}
		bad := p
		bad.Handler.SHA256 = strings.Repeat("0", 64)
		if VerifyDiscovery(root, bad, r).State != "rejected" {
			t.Fatal("stale hash accepted")
		}
		bad = p
		bad.Handler.Span.File = "../secret.js"
		if VerifyDiscovery(root, bad, r).State != "rejected" {
			t.Fatal("outside manifest accepted")
		}
		bad = p
		bad.Handler.ModelText = "invented model instruction"
		fixed := VerifyDiscovery(root, bad, r)
		if fixed.Handler.ModelText == bad.Handler.ModelText {
			t.Fatal("untrusted projection retained")
		}
	}
	if known != 1 || provisional != 1 {
		t.Fatalf("known %d provisional %d proposals %+v", known, provisional, ps)
	}
	if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(source+"\nchanged()"), 0600); err != nil {
		t.Fatal(err)
	}
	if VerifyDiscovery(root, ps[0], r).State != "rejected" {
		t.Fatal("changed source accepted")
	}
}
