package parse

import (
	"strings"
	"testing"
)

func TestP5EvalSinkHasNoDuplicateXSS(t *testing.T) {
	root := nextRepo(t, map[string]string{
		"pages/eval.js":   `import {useEffect,useState} from 'react'; export default function Page(){const [r,setR]=useState(''); useEffect(()=>{const u=new URLSearchParams(window.location.search).get('q'); eval("setResult('"+u+"')"); setTimeout("run('"+u+"')",1); new Function(u);},[]); return <div>{r}</div>}`,
		"pages/script.js": `export default function Page({q}){return <script dangerouslySetInnerHTML={{__html:"window.d="+q}}/>} export const getServerSideProps=async({query})=>({props:{q:query.q}});`,
		"pages/inner.js":  `export default function Page(){const u=new URLSearchParams(window.location.search).get('q'); document.getElementById('x').innerHTML=u; eval(u); return null}`,
	})
	r := analyzeNext(t, root)
	if got := len(usesOf(r, "code_execution_candidate", "pages/eval.js")); got != 3 {
		t.Errorf("code candidates: got %d want 3", got)
	}
	// Browser eval is code-owned; string timers and Function keep their
	// script-context XSS record (TestBrowserSourceSinkControls).
	evalXSS, otherXSS := 0, 0
	for _, u := range usesOf(r, "xss_candidate", "pages/eval.js") {
		if u.XSS == nil || u.XSS.OutputContext != "script" {
			continue
		}
		if strings.HasPrefix(u.Sink.Text, "eval") {
			evalXSS++
		} else {
			otherXSS++
		}
	}
	if evalXSS != 0 {
		t.Errorf("duplicate script-context XSS at eval sink: %d", evalXSS)
	}
	if otherXSS != 2 {
		t.Errorf("timer and Function script-context XSS: got %d want 2", otherXSS)
	}
	scripts := 0
	for _, u := range usesOf(r, "xss_candidate", "pages/script.js") {
		if u.XSS != nil && u.XSS.OutputContext == "script" {
			scripts++
		}
	}
	if scripts == 0 {
		t.Errorf("genuine script-context XSS at a non-eval sink must remain")
	}
	// A genuine HTML-sink XSS beside an eval in the same module remains.
	found := false
	for _, u := range usesOf(r, "xss_candidate", "pages/inner.js") {
		if u.XSS != nil && u.XSS.OutputContext != "script" {
			found = true
		}
	}
	if !found {
		t.Errorf("innerHTML XSS must remain")
	}
	if len(usesOf(r, "code_execution_candidate", "pages/inner.js")) != 1 {
		t.Errorf("eval code candidate must remain")
	}
}
