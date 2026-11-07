package judge

import (
	"context"
	"github.com/zazzcode/zazzles/internal/parse"
	"os"
	"path/filepath"
	"testing"
)

// A scalar source is not a protection flag: the same shared facts still allow
// shell syntax injection when the independently selected sink interprets text.
func TestNodeCommandSharedPipeline(t *testing.T) {
	for _, framework := range []string{"express", "fastify", "hapi"} {
		t.Run(framework, func(t *testing.T) {
			root := t.TempDir()
			source := `const {exec}=require('child_process');`
			switch framework {
			case "express":
				source += `const express=require('express');const app=express();app.get('/x/:id',(request,reply)=>exec('echo '+request.params.id,()=>{}));`
			case "fastify":
				source += `const fastify=require('fastify');const app=fastify();app.get('/x/:id',(request,reply)=>exec('echo '+request.params.id,()=>{}));`
			case "hapi":
				source += `const Hapi=require('@hapi/hapi');const app=Hapi.server();app.route({method:'GET',path:'/x/{id}',handler:(request,h)=>exec('echo '+request.params.id,()=>{})});`
			}
			if err := os.WriteFile(filepath.Join(root, "server.js"), []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			r, err := parse.Analyze(root, "")
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, u := range r.Uses {
				if u.Kind != "command_execution_candidate" {
					continue
				}
				count++
				if u.InputFacts == nil || u.InputFacts.Framework != framework {
					t.Fatal("shared input facts missing")
				}
				c, _ := commandStub(t, "openai", rawShell)
				a := c.Assess(context.Background(), u)
				if a.FindingStatus != "confirmed_vulnerability" {
					t.Fatalf("scalar acquisition incorrectly protected shell text: %+v", a)
				}
			}
			if count != 1 {
				t.Fatalf("command uses=%d", count)
			}
		})
	}
}
