package langjs

import "testing"

func TestCodeRedirectOperands(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"pages/api/unsafe.js": `import vm from 'node:vm'; export default function handler(req,res){ eval(req.body.code); new Function(req.body.params,req.body.code); vm.runInNewContext(req.body.code,{data:req.body.data}); res.redirect(req.query.to); }`,
		"pages/api/safe.js":   `import vm from 'node:vm'; export default function handler(req,res){ const eval=(v)=>v; eval(req.body.code); vm.runInNewContext('fixed(data)',{data:req.body.data}); res.redirect('https://trusted.example/path/'+req.query.to); }`,
		"app/client/page.tsx": `"use client"; import {useSearchParams} from 'next/navigation'; export default function Page(){const q=useSearchParams().get('q'); eval(q); setTimeout(q,10); setTimeout(()=>console.info(q),10); window.location.href=q; return null;}`,
	})
	r := analyzeNext(t, root)
	for _, row := range []struct {
		kind, file string
		count      int
	}{{"code_execution_candidate", "pages/api/unsafe.js", 4}, {"open_redirect_candidate", "pages/api/unsafe.js", 1}, {"code_execution_candidate", "pages/api/safe.js", 0}, {"open_redirect_candidate", "pages/api/safe.js", 0}, {"code_execution_candidate", "app/client/page.tsx", 2}, {"open_redirect_candidate", "app/client/page.tsx", 1}} {
		uses := usesOf(r, row.kind, row.file)
		if len(uses) != row.count {
			t.Errorf("%s %s: got %d want %d", row.kind, row.file, len(uses), row.count)
		}
		for _, u := range uses {
			if u.Completeness == nil {
				t.Errorf("missing completeness: %+v", u)
			} else if len(u.Completeness.Blockers) > 0 {
				t.Errorf("%s: blockers %+v", u.Sink.Text, u.Completeness.Blockers)
			}
		}
	}
}

func TestInterpreterBindingNegatives(t *testing.T) {
	r := analyzeNext(t, nextRepo(t, map[string]string{
		"pages/api/mutated.js": `import vm from 'node:vm';vm.runInContext=x=>x;export default function handler(req,res){vm.runInContext(req.body.code);res.end()}`,
		"app/patched/page.tsx": `"use client";window.eval=x=>x;export default function Page(){window.eval(location.hash);return null}`,
		"pages/api/shadow.js":  `import {Script as vm} from 'node:vm';import notevil from 'notevil';export default function handler(req,res){const eval=x=>x;(0,eval)(req.body.code);vm.runInContext(req.body.code);notevil.unrelated(req.body.code);let url='https://trusted.example/'+req.query.x;url=req.query.url;res.redirect(url);res.status(302);res.status(200);res.setHeader('Location',req.query.url);}`,
		"app/page.tsx":         `"use client";export default function Page(){function local(window){window.location.href=location.hash}local({location:{}});return null}`,
	}))
	if n := len(usesOf(r, "code_execution_candidate", "")); n != 0 {
		t.Fatalf("shadowed or unrelated interpreter bindings: %d", n)
	}
	redirects := usesOf(r, "open_redirect_candidate", "")
	if len(redirects) != 1 || redirects[0].Sink.Text != "res.redirect(url)" {
		t.Fatalf("redirect binding/reassignment: %+v", redirects)
	}
}

func TestInterpreterVMContextAndResponseHelper(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.js", `const express=require('express');const app=express();const vm=require('node:vm');const safeEval=require('notevil');function sendTo(url,reply){return reply.redirect(url)}app.post('/x',(req,res)=>{const sandbox={safeEval,code:req.body.code};vm.createContext(sandbox);vm.runInContext('safeEval(code)',sandbox);sendTo(req.body.next,res);});`)
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	codes := usesOf(r, "code_execution_candidate", "")
	if len(codes) != 1 || codes[0].Code.ContractID != "js-safe-eval-libs-v1" {
		t.Fatalf("sandbox evaluator: %+v", codes)
	}
	redirects := usesOf(r, "open_redirect_candidate", "")
	if len(redirects) != 1 {
		t.Fatalf("response helper records=%d", len(redirects))
	}
	for _, u := range append(codes, redirects...) {
		if u.Completeness == nil || len(u.Completeness.Blockers) > 0 {
			t.Errorf("%s: %+v", u.Sink.Text, u.Completeness)
		}
	}
}
