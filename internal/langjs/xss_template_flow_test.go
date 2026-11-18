package langjs

import "testing"

func TestCompiledTemplateFlows(t *testing.T) {
	tests := []struct{ name, body, protection, context string }{
		{"request inserted before compile", "let template=fs.readFileSync('views/page.pug','utf8');template=template.replace('_name_',req.query.name);const render=pug.compile(template);res.send(render())", "raw", "template_code"},
		{"dynamic import compiler", "let template=fs.readFileSync('views/page.pug','utf8');template=template.replace('_name_',req.query.name);const pug=(await import('pug')).default;const render=pug.compile(template);res.send(render())", "raw", "template_code"},
		{"file callback", "fs.readFile('views/page.pug',function(err,buffer){let template=buffer.toString();template=template.replace('_name_',req.query.name);const render=pug.compile(template);res.send(render())})", "raw", "template_code"},
		{"HTML encoder is not template encoding", "let template=fs.readFileSync('views/page.pug','utf8');template=template.replace('_name_',entities.encode(req.query.name));res.send(pug.compile(template)())", "unknown", "template_code"},
		{"plain constant template", "const template=fs.readFileSync('views/page.pug','utf8');const render=pug.compile(template);res.send(render())", "", ""},
		{"fake compiler not trusted", "const fake={compile:x=>x};res.send(fake.compile(req.query.name))", "unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "app.ts", "import express from 'express';import fs from 'node:fs';import pug from 'pug';import * as entities from 'entities';const app=express();app.get('/x',async(req,res)=>{"+tt.body+"})")
			writeSource(t, root, "views/page.pug", "p _name_")
			r, err := Analyze(root, "app.ts")
			if err != nil {
				t.Fatal(err)
			}
			uses := xssUses(r)
			if tt.protection == "" {
				if len(uses) > 0 {
					t.Fatalf("unexpected use: %+v", uses)
				}
				return
			}
			if len(uses) != 1 || uses[0].XSS.Protection != tt.protection || uses[0].XSS.OutputContext != tt.context {
				t.Fatalf("want %s/%s; got %+v", tt.protection, tt.context, uses)
			}
		})
	}
}
