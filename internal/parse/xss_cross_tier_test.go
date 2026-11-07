package parse

import (
	"strings"
	"testing"
)

func TestCrossTierResponseFieldLinks(t *testing.T) {
	route := "app.get('/rest/item/:id',(req,res)=>{db.find({}).then((rows)=>{const result:any={data:[]};result.data[0]={name:%s};res.json(result)})});"
	tests := []struct {
		name, server, field, extra, protection string
		resolved                               bool
		gap                                    string
	}{
		{"request field reaches trusted HTML", "req.params.id", "name", "", "raw", true, ""},
		{"line-break removal keeps markup", "req.params.id.replace(/(\\r\\n|\\n|\\r)/gm,'')", "name", "", "raw", true, ""},
		{"allow-list replacement protects", "String(req.params.id).replace(/[^\\w-]+/g,'')", "name", "", "sanitized", true, ""},
		{"partial escaping is not modeled", "req.params.id.replace(/>/g,'')", "name", "", "unknown", true, ""},
		{"removing every < protects HTML text", "req.params.id.replace(/</g,'')", "name", "", "sanitized", true, ""},
		{"different response field stays unresolved", "req.params.id", "other", "", "raw", false, "response_field_unresolved"},
		{"constant response has no producer", "'fixed'", "name", "", "raw", false, "response_producer_unresolved"},
		{"ambiguous producer routes", "req.params.id", "name", "app.get('/rest/:kind/:id',(req,res)=>{res.json({data:[{name:req.params.kind}]})});", "raw", false, "response_producer_unresolved"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", "import express from 'express';const app=express();"+strings.Replace(route, "%s", tt.server, 1)+tt.extra)
			writeSource(t, root, "client/item.service.ts", "import {HttpClient} from '@angular/common/http';import {Injectable,inject} from '@angular/core';@Injectable() export class ItemService {private readonly http=inject(HttpClient);private readonly host='/rest/item';find(id:any){return this.http.get(`${this.host}/${id}`)}}")
			writeSource(t, root, "client/page.component.ts", "import {Component,inject} from '@angular/core';import {DomSanitizer} from '@angular/platform-browser';import {ItemService} from './item.service';@Component({templateUrl:'./page.html'}) export class Page {private items=inject(ItemService);private sanitizer=inject(DomSanitizer);public results:any={};run(){this.items.find(1).subscribe((r)=>{this.results.name=this.sanitizer.bypassSecurityTrustHtml(`<b>${r.data[0]."+tt.field+"}</b>`)})}}")
			writeSource(t, root, "client/page.html", `<span [innerHTML]="results.name"></span>`)
			r, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, u := range xssUses(r) {
				if u.EntryKind != "browser" || u.XSS.Type != "cross_tier" {
					continue
				}
				found = true
				if u.XSS.OriginResolved != tt.resolved || u.XSS.Protection != tt.protection || u.XSS.ResponseField != "data[]."+tt.field {
					t.Fatalf("want resolved=%v protection=%s field=%s; got %+v", tt.resolved, tt.protection, tt.field, u.XSS)
				}
				if tt.resolved {
					if len(u.XSS.RelatedEntries) != 1 || testEntryPath(r, u.XSS.RelatedEntries[0]) != "/rest/item/:id" || !strings.Contains(u.Dependencies[0].Source.Text, "req.params.id") {
						t.Fatalf("server origin missing: %+v %+v", u.XSS, u.Dependencies)
					}
				}
				if tt.gap != "" {
					hit := false
					for _, g := range u.Gaps {
						hit = hit || g.Kind == tt.gap
					}
					if !hit {
						t.Fatalf("missing gap %s: %+v", tt.gap, u.Gaps)
					}
				}
			}
			if !found {
				t.Fatalf("no cross-tier record: %+v", xssUses(r))
			}
		})
	}
}
