package langpy

import "testing"

func TestPythonInlineFetchMethodGap(t *testing.T) {
	root := pythonFixture(t, map[string]string{"app.py": "from flask import Flask,render_template\napp=Flask(__name__)\n@app.get('/')\ndef index():\n    return render_template('page.html')\n", "templates/page.html": `<script>fetch('/item',{method:verb}).then(r=>r.json()).then(r=>{document.body.innerHTML=r.name})</script>`})
	r, err := Analyze(root, "")
	if err != nil {
		t.Fatal(err)
	}
	uses := xssUses(r)
	if len(uses) != 1 || uses[0].XSS.OriginResolved || uses[0].XSS.ResponseMethod != "" {
		t.Fatalf("inline unresolved method lost: %+v", uses)
	}
	hit := false
	for _, g := range uses[0].Gaps {
		hit = hit || g.Kind == "response_method_unresolved"
	}
	if !hit {
		t.Fatal("inline method gap lost")
	}
}
