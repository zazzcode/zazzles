package parse

import (
	"strings"
	"testing"
)

func TestBrowserServerRequestIsolation(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express=require('express');const app=express();app.get('/item',(req,res)=>{fetch(req.query.destination);res.json({name:req.query.name})});`)
	writeSource(t, root, "client.js", `fetch('/item').then(r=>r.json()).then(r=>{document.body.innerHTML=r.name});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	outbound, render := 0, 0
	for _, u := range r.Uses {
		// The server call's destination is a request value, so it is an SSRF claim;
		// the browser fetch never becomes a server outbound record.
		if u.Kind == "outbound_http_candidate" || u.Kind == "ssrf_candidate" {
			outbound++
			if u.Kind != "ssrf_candidate" || u.Sink.Span.File != "server.js" || u.XSS != nil || u.Components == nil || u.Components.Pack.ID != "pack.ssrf" {
				t.Fatal("browser/server observations conflated")
			}
			if len(u.Dependencies) != 1 || !strings.Contains(u.Dependencies[0].Source.Text, "req.query.destination") {
				t.Fatal("server destination borrowed browser response")
			}
		}
		if u.Kind == "xss_candidate" && u.XSS != nil && u.XSS.Type == "cross_tier" {
			render++
			if u.Sink.Span.File != "client.js" || !u.XSS.OriginResolved || u.XSS.ResponseField != "name" || len(u.XSS.RelatedEntries) != 1 {
				t.Fatalf("browser producer link: %+v gaps=%+v", u.XSS, u.Gaps)
			}
			if len(u.Dependencies) != 1 || !strings.Contains(u.Dependencies[0].Source.Text, "req.query.name") {
				t.Fatal("request destination became response")
			}
			if u.Components == nil || u.Components.Pack.ID != "pack.xss" {
				t.Fatal("rendering claim became outbound")
			}
		}
	}
	if outbound != 1 || render != 1 {
		t.Fatalf("outbound=%d render=%d", outbound, render)
	}
}
