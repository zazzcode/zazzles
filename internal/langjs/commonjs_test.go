package langjs

import "testing"

func TestCommonJSRouteBindings(t *testing.T) {
	tests := []struct {
		name, entry, handlers string
		entries, resolved     int
	}{
		{"named export", "const express=require('express');const app=express();const routes=require('./routes');app.get('/x',routes.index)", "exports.index=function(req,res){res.send(req.query.q)}", 1, 1},
		{"module named export", "const express=require('express');const app=express();const routes=require('./routes');app.get('/x',routes.index)", "module.exports.index=(req,res)=>res.send(req.query.q)", 1, 1},
		{"default function", "const express=require('express');const app=express();const handler=require('./routes');app.get('/x',handler)", "module.exports=function(req,res){res.send(req.query.q)}", 1, 1},
		{"object export", "const express=require('express');const app=express();const routes=require('./routes');app.get('/x',routes.index)", "module.exports={index:(req,res)=>res.send(req.query.q)}", 1, 1},
		{"nested exported object", "const express=require('express');const app=express();const routes=require('./routes');app.get('/x',routes.chat.get)", "exports.chat={get:(req,res)=>res.send(req.query.q)}", 1, 1},
		{"loader shadow", "function require(x){return fake};const express=require('express');const app=express();app.get('/x',(req,res)=>{})", "", 0, 0},
		{"express reassigned", "let express=require('express');express=fake;const app=express();app.get('/x',(req,res)=>{})", "", 0, 0},
		{"handler import reassigned", "const express=require('express');const app=express();let routes=require('./routes');routes=other;app.get('/x',routes.index)", "exports.index=(req,res)=>{}", 1, 0},
		{"handler lexical shadow", "const express=require('express');const app=express();const routes=require('./routes');function register(routes){app.get('/x',routes.index)}", "exports.index=(req,res)=>{}", 1, 0},
		{"fake express package", "const express=require('other');const app=express();app.get('/x',(req,res)=>{})", "", 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.js", tt.entry)
			writeSource(t, root, "routes/index.js", tt.handlers)
			r, err := Analyze(root, "app.js")
			if err != nil {
				t.Fatal(err)
			}
			for _, reg := range r.Registrations {
				if reg.DeclaredHandler == nil || len(reg.SyntaxSteps) == 0 {
					t.Fatal("unresolved dispatch lost its declaration syntax")
				}
			}
			resolved := 0
			for _, entry := range r.Entries {
				if r.Handler(entry.ID) != nil {
					resolved++
				}
			}
			if len(r.Entries) != tt.entries || resolved != tt.resolved {
				t.Fatalf("entries/resolved=%d/%d, want %d/%d: %+v", len(r.Entries), resolved, tt.entries, tt.resolved, r.Entries)
			}
		})
	}
}
