package parse

import (
	"fmt"
	"strings"
	"testing"
)

func TestStoredTemplatePathsAndControls(t *testing.T) {
	tests := []struct {
		name, write, template, version, protection string
		resolved                                   bool
	}{
		{"raw stored field", "new Note({body:req.body.text}).save()", `<% notes.forEach(function(note){ %><%- note.body %><% }); %>`, "0.3.5", "raw", true},
		{"escaped stored field", "new Note({body:req.body.text}).save()", `<% notes.forEach(function(note){ %><%= note.body %><% }); %>`, "0.3.5", "encoded", true},
		{"old Markdown sanitizer", "new Note({body:req.body.text}).save()", `<% notes.forEach(function(note){ %><%- marked(new String(note.body)) %><% }); %>`, "0.3.5", "ineffective", true},
		{"unknown Markdown version", "new Note({body:req.body.text}).save()", `<% notes.forEach(function(note){ %><%- marked(new String(note.body)) %><% }); %>`, "^0.3.5", "unknown", true},
		{"mismatched field", "new Note({other:req.body.text}).save()", `<% notes.forEach(function(note){ %><%- note.body %><% }); %>`, "0.3.5", "raw", false},
		{"unknown write transform", "new Note({body:opaque(req.body.text)}).save()", `<% notes.forEach(function(note){ %><%- note.body %><% }); %>`, "0.3.5", "unknown", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const mongoose=require('mongoose');const marked=require('marked');const Note=mongoose.model('Note');const app=express();app.set('view engine','ejs');app.locals.marked=marked;app.post('/write',(req,res)=>{"+tt.write+"});app.get('/read',(req,res)=>{Note.find({}).exec(function(err,notes){res.render('page',{notes})})})")
			writeSource(t, root, "views/page.ejs", tt.template)
			writeSource(t, root, "package.json", `{"dependencies":{"marked":"`+tt.version+`"}}`)
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Type != "stored" || uses[0].XSS.OriginResolved != tt.resolved || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want stored resolved=%v protection=%s; got %+v", tt.resolved, tt.protection, uses)
			}
			if tt.resolved {
				if len(uses[0].XSS.RelatedEntries) == 0 || testEntryPath(r, uses[0].XSS.RelatedEntries[0]) != "/write" {
					t.Fatal("write entry link missing")
				}
				if !strings.Contains(uses[0].Dependencies[0].Source.Text, "req.body.text") {
					t.Fatal("original request source missing")
				}
			}
		})
	}
}

func TestStoredWritePathsStaySeparate(t *testing.T) {
	update := "app.post('/update/:id',(req,res)=>{Note.findById(req.params.id,function(err,note){note.body=%s;note.save(function(err){res.redirect('/')})})});"
	tests := []struct {
		name, create, update, protection string
		paths                            []string
	}{
		// An unresolved helper on one create branch must not hide the raw sibling branch or the raw update write.
		{"supported unsafe beside unknown sibling", "var item=req.body.text;if(typeof item=='string'&&item.length>3){console.log('long')}else{item=opaque(item)}new Note({body:item}).save()",
			"req.body.text", "raw", []string{"raw", "unknown", "raw"}},
		// An encoded path does not protect an unresolved sibling.
		{"unknown sibling is not protected", "var item=escapeHtml(req.body.text);if(flag(req)){item=opaque(req.body.text)}new Note({body:item}).save()",
			"escapeHtml(req.body.text)", "unknown", []string{"unknown", "encoded", "encoded"}},
		{"every path protected", "var item=req.body.text;if(flag(req)){item=escapeHtml(item)}else{item=escapeHtml(item.trim())}new Note({body:item}).save()",
			"escapeHtml(req.body.text)", "sanitized", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const mongoose=require('mongoose');const escapeHtml=require('escape-html');const Note=mongoose.model('Note');const app=express();app.set('view engine','ejs');"+
				"app.post('/create',(req,res)=>{"+tt.create+"});"+fmt.Sprintf(update, tt.update)+
				"app.get('/',(req,res)=>{Note.find({}).exec(function(err,notes){res.render('page',{notes})})})")
			writeSource(t, root, "views/page.ejs", `<% notes.forEach(function(note){ %><%- note.body %><% }); %>`)
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || !uses[0].XSS.OriginResolved || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want resolved stored protection=%s; got %+v", tt.protection, uses)
			}
			u := uses[0]
			seen := map[string]bool{}
			for _, d := range u.Dependencies {
				if k := dependencyKey(d); seen[k] {
					t.Fatalf("duplicate source path %s", k)
				} else {
					seen[k] = true
				}
			}
			var got []string
			for i, p := range u.XSS.Paths {
				if p.Dependency != i || p.Entry == "" {
					t.Fatalf("path %d lacks its dependency or writing entry: %+v", i, p)
				}
				got = append(got, p.Protection)
			}
			if strings.Join(got, ",") != strings.Join(tt.paths, ",") {
				t.Fatalf("paths %v, want %v", got, tt.paths)
			}
			if len(tt.paths) > 0 && testEntryPath(r, u.XSS.Paths[len(u.XSS.Paths)-1].Entry) != "/update/:id" {
				t.Fatalf("update write entry missing: %+v", u.XSS.Paths)
			}
		})
	}
}

func TestBranchPathsAndPreconditions(t *testing.T) {
	tests := []struct {
		name, body, protection string
		branchKinds            []string
	}{
		{"else branch is traversed", "let v=req.query.q;if(req.query.a){v=escapeHtml(v)}else{v=opaque(v)}res.send('<p>'+v+'</p>')", "unknown", []string{"branch_true_precondition", "branch_false_precondition"}},
		{"if without else keeps the skipped path under the false test", "let v=req.query.q;if(req.query.a){v=escapeHtml(v)}res.send('<p>'+v+'</p>')", "raw", []string{"branch_true_precondition", "branch_false_precondition"}},
		{"returning branch does not reach the sink", "let v=escapeHtml(req.query.q);if(req.query.a){v=req.query.q;return res.end()}res.send('<p>'+v+'</p>')", "sanitized", []string{""}},
		{"single-statement branches", "let v=req.query.q;if(req.query.a) v=escapeHtml(v); else /* both */ v=escapeHtml(v);res.send('<p>'+v+'</p>')", "sanitized", []string{"branch_true_precondition", "branch_false_precondition"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", "const express=require('express');const escapeHtml=require('escape-html');const app=express();app.get('/x',(req,res)=>{"+tt.body+"})")
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection {
				t.Fatalf("want protection=%s; got %+v", tt.protection, uses)
			}
			var kinds []string
			for _, d := range uses[0].Dependencies {
				if !strings.Contains(d.Source.Text, "req.query.q") {
					continue
				}
				kind := ""
				for _, e := range d.Transfers {
					if strings.HasPrefix(e.Kind, "branch_") {
						kind = e.Kind
					}
				}
				kinds = append(kinds, kind)
			}
			if strings.Join(kinds, ",") != strings.Join(tt.branchKinds, ",") {
				t.Fatalf("branch preconditions %v, want %v", kinds, tt.branchKinds)
			}
		})
	}
}
