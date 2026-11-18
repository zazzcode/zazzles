package langjs

import (
	"strings"
	"testing"
)

func TestRequestLineLogging(t *testing.T) {
	const head = "import express from 'express';import morgan from 'morgan';const app=express();"
	const change = "app.get('/rest/user/change-password',({ query, connection },res)=>{const pw=query.new;user.update({ password: pw })})"
	tests := []struct {
		name, src, gap string
	}{
		{"destructured query written to password", head + "app.use(morgan('combined'));" + change, "log_request_line_credential"},
		{"request query written to password", head + "app.use(morgan('tiny'));app.get('/x',(req,res)=>{user.update({ password: req.query.next })})", "log_request_line_credential"},
		{"custom format with url", head + "app.use(morgan(':method :url :status'));" + change, "log_request_line_credential"},
		{"query compared with stored password", head + "app.use(morgan('combined'));app.get('/x',({ query },res)=>{if (hash(query.current) !== user.data.password) { return }})", "log_request_line_credential"},
		{"credential-named query key", head + "app.use(morgan('dev'));app.get('/x',(req,res)=>{res.send(lookup(req.query.token))})", "log_request_line_hint"},
		{"conditional registration", head + "if (process.env.LOG) { app.use(morgan('combined')) };" + change, "log_request_line_conditional"},
		{"skip option", head + "app.use(morgan('combined', { skip: (req) => false }));" + change, "log_request_line_conditional"},
		{"matching path prefix", head + "app.use('/rest', morgan('combined'));" + change, "log_request_line_credential"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", tt.src)
			report, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			uses := logUses(report)
			if len(uses) != 1 || !gapKind(uses[0].Gaps, tt.gap) {
				t.Fatalf("log uses=%+v", uses)
			}
			if !strings.Contains(uses[0].Sink.Text, "morgan(") || len(uses[0].Dependencies) == 0 {
				t.Fatalf("sink or dependency missing: %+v", uses[0])
			}
		})
	}
}

func TestRequestLineLoggingNegativeControls(t *testing.T) {
	const head = "import express from 'express';import morgan from 'morgan';const app=express();"
	const change = "app.get('/rest/user/change-password',({ query },res)=>{user.update({ password: query.new })})"
	tests := []struct{ name, src string }{
		{"registered after the route", head + change + ";app.use(morgan('combined'))"},
		{"format without url", head + "app.use(morgan(':method :status'));" + change},
		{"dynamic format", head + "app.use(morgan(fmt));" + change},
		{"other receiver", head + "const admin=express();admin.use(morgan('combined'));" + change},
		{"other path prefix", head + "app.use('/api', morgan('combined'));" + change},
		{"body credential is not in the URL", head + "app.use(morgan('combined'));app.post('/x',(req,res)=>{user.update({ password: req.body.next })})"},
		{"comparison with a non-credential property", head + "app.use(morgan('combined'));app.get('/x',({ query },res)=>{if (query.page !== user.data.lastPage) { return }})"},
		{"non-credential query field", head + "app.use(morgan('combined'));app.get('/x',(req,res)=>{res.send(req.query.page)})"},
		{"fake morgan", "import express from 'express';function morgan(f){return (q,s,n)=>n()};const app=express();app.use(morgan('combined'));" + change},
		{"no request logging", "import express from 'express';const app=express();" + change},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", tt.src)
			report, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			if uses := logUses(report); len(uses) != 0 {
				t.Fatalf("unexpected log use: %+v", uses)
			}
		})
	}
}

func TestDestructuredRequestParameters(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.get('/x',({ query, connection },res)=>{console.log(query.token)})")
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	uses := logUses(report)
	if len(uses) != 1 || uses[0].Dependencies[0].Source.Text != "query.token" {
		t.Fatalf("destructured source not resolved: %+v", uses)
	}
	if gapKind(uses[0].Gaps, "request_projection_unresolved") || !gapKind(uses[0].Gaps, "request_projection_partial") {
		t.Fatalf("projection gaps=%+v", uses[0].Gaps)
	}
	t.Run("shadowed container", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.get('/x',({ query },res)=>{const query2=1;{};console.log(query.token)})")
		if _, err := Analyze(root, "server.ts"); err != nil {
			t.Fatal(err)
		}
		writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.get('/x',({ query },res)=>{const query={token:'x'};console.log(query.token)})")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		if uses := logUses(report); len(uses) != 0 {
			t.Fatalf("local query treated as request: %+v", uses)
		}
	})
}
