package parse

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/internal/analysis"
)

func logUses(report *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range report.Uses {
		if u.Kind == "log_sink_candidate" {
			out = append(out, u)
		}
	}
	return out
}

func TestLogSinkClassification(t *testing.T) {
	tests := []struct {
		name, body, gap, detail string
	}{
		{"authorization header", "console.log('auth', req.headers.authorization)", "log_protocol_credential", "headers field authorization"},
		{"subscript header", "console.info(req.headers['authorization'])", "log_protocol_credential", "authorization"},
		{"password in SQL text", "const {username,password}=req.body;const q=`SELECT '${username}' '${password}'`;console.log('Query:', q)", "log_sensitive_field_hint", "field password"},
		{"personal data", "console.warn('user', req.body.email)", "log_sensitive_field_hint", "personal-data"},
		{"cookie value", "console.log(req.cookies.session)", "log_sensitive_field_hint", "cookie"},
		{"whole body", "console.log(req.body)", "log_request_container", "whole request body"},
		{"stringified body", "console.log(JSON.stringify(req.body))", "log_request_container", "whole request body"},
		{"content-preserving trim", "console.log(req.body.password.trim())", "log_sensitive_field_hint", "password"},
		{"direct length", "console.log('len', req.body.password.length)", "log_non_content_only", "password"},
		{"local length", "const p=req.body.password;console.log(p.length)", "log_non_content_only", "password"},
		{"comparison", "const p=req.body.password;console.log('match', p === 'x')", "log_non_content_only", "password"},
		{"presence", "console.log(Boolean(req.headers.authorization))", "log_non_content_only", "authorization"},
		{"unresolved masking", "console.log(mask(req.body.password))", "log_transform_unresolved", "mask(req.body.password)"},
		{"replace may redact", "console.log(req.body.password.replace(/./g, '*'))", "log_transform_unresolved", "replace"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.post('/x',(req,res)=>{"+tt.body+"})")
			report, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			uses := logUses(report)
			if len(uses) != 1 {
				t.Fatalf("log uses=%d: %+v", len(uses), report.Uses)
			}
			u := uses[0]
			found := false
			for _, g := range u.Gaps {
				if g.Kind == tt.gap && strings.Contains(g.Detail, tt.detail) {
					found = true
				}
			}
			if !found {
				t.Fatalf("missing %s containing %q: %+v", tt.gap, tt.detail, u.Gaps)
			}
			if !gapKind(u.Gaps, "log_destination_unresolved") || u.Assessment.Status != "not_run" {
				t.Fatalf("destination limit or offline status missing: %+v", u)
			}
			binding := false
			for _, e := range u.Context {
				binding = binding || e.Kind == "logger_binding"
			}
			if !binding {
				t.Fatal("logger binding evidence missing")
			}
		})
	}
}

func TestLogSinkNegativeControls(t *testing.T) {
	tests := []struct{ name, prefix, body string }{
		{"constant message", "", "console.log('started')"},
		{"non-sensitive field", "", "console.log('page', req.query.page)"},
		{"username is not a credential hint", "", "console.log(req.body.username)"},
		{"handler-shadowed console", "", "const console={log(){}};console.log(req.headers.authorization)"},
		{"module-shadowed console", "const console={log(){}};", "console.log(req.headers.authorization)"},
		{"local fake logger", "", "const logger={info(){}};logger.info(req.headers.authorization)"},
		{"module fake logger", "const logger={info:()=>{}};", "logger.info(req.headers.authorization)"},
		{"unknown logging library", "import bunyan from 'bunyan';const logger=bunyan.createLogger();", "logger.info(req.headers.authorization)"},
		{"local pino lookalike", "const pino=()=>({info(){}});const logger=pino();", "logger.info(req.headers.authorization)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			writeSource(t, root, "server.ts", "import express from 'express';"+tt.prefix+"const app=express();app.post('/x',(req,res)=>{"+tt.body+"})")
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

func TestWinstonLoggerBindings(t *testing.T) {
	cases := []struct{ name, logger, server string }{
		{"default export", "import * as winston from 'winston';export default winston.createLogger({transports:[]})",
			"import express from 'express';import logger from './lib/logger';const app=express();app.get('/x',(req,res)=>{logger.warn('token '+req.query.token)})"},
		{"named export", "import winston from 'winston';export const log=winston.createLogger({})",
			"import express from 'express';import {log} from './lib/logger';const app=express();app.get('/x',(req,res)=>{log.info(req.query.token)})"},
		{"same module", "",
			"import express from 'express';import {createLogger} from 'winston';const logger=createLogger({});const app=express();app.get('/x',(req,res)=>{logger.error(req.query.token)})"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			if tt.logger != "" {
				writeSource(t, root, "lib/logger.ts", tt.logger)
			}
			writeSource(t, root, "server.ts", tt.server)
			report, err := Analyze(root, "server.ts")
			if err != nil {
				t.Fatal(err)
			}
			uses := logUses(report)
			if len(uses) != 1 || !gapKind(uses[0].Gaps, "log_sensitive_field_hint") {
				t.Fatalf("winston use=%+v", uses)
			}
		})
	}
	t.Run("fake default export", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "lib/logger.ts", "export default {warn(){}}")
		writeSource(t, root, "server.ts", "import express from 'express';import logger from './lib/logger';const app=express();app.get('/x',(req,res)=>{logger.warn(req.query.token)})")
		report, err := Analyze(root, "server.ts")
		if err != nil {
			t.Fatal(err)
		}
		if uses := logUses(report); len(uses) != 0 {
			t.Fatalf("fake logger accepted: %+v", uses)
		}
	})
}

func TestLoggerIsNotAValidator(t *testing.T) {
	root := t.TempDir()
	writeSource(t, root, "server.ts", "import express from 'express';const app=express();app.post('/x',(req,res)=>{console.log(req.body.password)})")
	report, err := Analyze(root, "server.ts")
	if err != nil {
		t.Fatal(err)
	}
	v := kindUse(t, report, "input_validation_candidate")
	if !gapKind(v.Gaps, "input_validation_absent") || gapKind(v.Gaps, "input_validation_unresolved") {
		t.Fatalf("logging changed validation evidence: %+v", v.Gaps)
	}
}

func TestGlobalLoggerSourceSnapshot(t *testing.T) {
	for _, callee := range []string{"console.log", "console.info", "console.warn", "console.error", "console /* binding comment */ .debug"} {
		t.Run(callee, func(t *testing.T) {
			root := t.TempDir()
			source := "import express from 'express';const app=express();app.post('/x',(req,res)=>{" + callee + "(req.headers.authorization)})"
			writeSource(t, root, "server.js", source)
			r, err := Analyze(root, "server.js")
			if err != nil {
				t.Fatal(err)
			}
			uses := logUses(r)
			if len(uses) != 1 {
				t.Fatalf("logger uses=%d", len(uses))
			}
			found := false
			for _, e := range uses[0].Context {
				if e.Kind != "logger_binding" {
					continue
				}
				found = true
				if e.Text != source[e.Span.StartByte:e.Span.EndByte] {
					t.Fatalf("logger evidence rewrites source: %q vs %q", e.Text, source[e.Span.StartByte:e.Span.EndByte])
				}
				if e.SHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte(source))) {
					t.Fatal("logger source hash mismatch")
				}
				if strings.Contains(e.ModelText, "binding comment") {
					t.Fatal("logger model projection leaked source comments")
				}
			}
			if !found {
				t.Fatal("verified global logger evidence missing")
			}
		})
	}
}

func TestRequireDestructuring(t *testing.T) {
	t.Run("winston createLogger", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {createLogger}=require('winston');const logger=createLogger({});const app=express();app.get('/x',(req,res)=>{logger.error(req.query.token);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		uses := logUses(report)
		if len(uses) != 1 || !gapKind(uses[0].Gaps, "log_sensitive_field_hint") {
			t.Fatalf("winston destructure missed: %+v", uses)
		}
	})
	t.Run("winston aliased createLogger", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {createLogger: make}=require('winston');const logger=make({});const app=express();app.get('/x',(req,res)=>{logger.warn(req.query.token);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		if uses := logUses(report); len(uses) != 1 {
			t.Fatalf("aliased winston destructure missed: %+v", uses)
		}
	})
	t.Run("fake winston module rejected", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {createLogger}=require('not-winston');const logger=createLogger({});const app=express();app.get('/x',(req,res)=>{logger.error(req.query.token);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		if uses := logUses(report); len(uses) != 0 {
			t.Fatalf("fake winston accepted: %+v", uses)
		}
	})
	t.Run("sequelize constructor", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {Sequelize}=require('sequelize');const db=new Sequelize('sqlite::memory:');const app=express();app.get('/x',(req,res)=>{db.query('SELECT '+req.query.q);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		u := kindUse(t, report, "sql_query_candidate")
		if u.APIModel == nil || u.APIModel.Library != "sequelize" || u.APIModel.ID != "sequelize-raw-query-v1" {
			t.Fatalf("sequelize destructure unbound: api=%+v gaps=%+v", u.APIModel, u.Gaps)
		}
		if len(u.Completeness.Evidence["sink_binding"]) == 0 {
			t.Fatalf("verified sink_binding evidence missing: %+v", u.Completeness)
		}
	})
	t.Run("sequelize aliased constructor", func(t *testing.T) {
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const {Sequelize: ORM}=require('sequelize');const db=new ORM('sqlite::memory:');const app=express();app.get('/x',(req,res)=>{db.query('SELECT '+req.query.q);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		u := kindUse(t, report, "sql_query_candidate")
		if u.APIModel == nil || u.APIModel.Library != "sequelize" {
			t.Fatalf("aliased sequelize destructure unbound: %+v", u.APIModel)
		}
	})
	t.Run("bare require still unbound without member name", func(t *testing.T) {
		// const Sequelize=require('sequelize') records name "*"; ctor check wants "Sequelize".
		root := t.TempDir()
		writeSource(t, root, "server.js", `const express=require('express');const Sequelize=require('sequelize');const db=new Sequelize('sqlite::memory:');const app=express();app.get('/x',(req,res)=>{db.query('SELECT '+req.query.q);res.end()});`)
		report, err := Analyze(root, "server.js")
		if err != nil {
			t.Fatal(err)
		}
		u := kindUse(t, report, "sql_query_candidate")
		if u.APIModel != nil && u.APIModel.Library == "sequelize" && !gapKind(u.Gaps, "sink_binding_unverified") {
			t.Fatalf("bare require unexpectedly bound as named Sequelize: %+v", u.APIModel)
		}
	})
}
