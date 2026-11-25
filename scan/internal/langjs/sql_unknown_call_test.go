package langjs

import (
	"strings"
	"testing"

	"github.com/zazzcode/zazzles/scan/internal/analysis"
	"github.com/zazzcode/zazzles/scan/internal/analysispacks"
)

// sqlCallForm is one Express application; the handler reads req.query.id.
type sqlCallForm struct {
	name, imports, setup, body string
	files                      map[string]string
}

func sqlCallApp(f sqlCallForm) map[string]string {
	files := map[string]string{"app.js": "import express from 'express'\n" + f.imports + "\nconst app = express()\n" + f.setup +
		"\napp.get('/r', async (req, res) => {\n  const id = req.query.id\n  " + f.body + "\n  res.json({})\n})\napp.listen(3000)\n"}
	for name, src := range f.files {
		files[name] = src
	}
	return files
}

const unsafeText = "`SELECT * FROM users WHERE id = ${id}`"

// sqlCallPositives are the sixteen driver and wrapper forms of the probe, then
// three receiver shapes.
var sqlCallPositives = []sqlCallForm{
	{name: "pool_query_no_contract", imports: "import { Pool } from 'pg'", setup: "const pool = new Pool()", body: "await pool.query(" + unsafeText + ")"},
	{name: "mysql2_query", imports: "import mysql from 'mysql2/promise'", setup: "const db = await mysql.createConnection({})", body: "await db.query(" + unsafeText + ")"},
	{name: "mysql2_execute", imports: "import mysql from 'mysql2/promise'", setup: "const db = await mysql.createConnection({})", body: "await db.execute(" + unsafeText + ")"},
	{name: "mssql", imports: "import sql from 'mssql'", setup: "const pool = await sql.connect({})", body: "await pool.request().query(" + unsafeText + ")"},
	{name: "typeorm", imports: "import { DataSource } from 'typeorm'", setup: "const source = new DataSource({})", body: "await source.query(" + unsafeText + ")"},
	{name: "clickhouse", imports: "import { createClient } from '@clickhouse/client'", setup: "const client = createClient({})", body: "await client.query({ query: " + unsafeText + ", format: 'JSON' })"},
	{name: "sqlite3", imports: "import sqlite3 from 'sqlite3'", setup: "const db = new sqlite3.Database(':memory:')", body: "db.all(" + unsafeText + ", () => {})"},
	{name: "oracledb", imports: "import oracledb from 'oracledb'", setup: "const conn = await oracledb.getConnection({})", body: "await conn.execute(" + unsafeText + ")"},
	{name: "postgres_unsafe", imports: "import postgres from 'postgres'", setup: "const sql = postgres('postgres://x')", body: "await sql.unsafe(" + unsafeText + ")"},
	{name: "knex_raw", imports: "import knex from 'knex'", setup: "const db = knex({ client: 'pg' })", body: "await db.raw(" + unsafeText + ")"},
	{name: "drizzle_raw", imports: "import { drizzle } from 'drizzle-orm/node-postgres'\nimport { sql } from 'drizzle-orm'", setup: "const db = drizzle('postgres://x')", body: "await db.execute(sql.raw(" + unsafeText + "))"},
	{name: "libsql", imports: "import { createClient } from '@libsql/client'", setup: "const client = createClient({ url: 'file:x' })", body: "await client.execute({ sql: " + unsafeText + ", args: [] })"},
	{name: "duckdb", imports: "import { DuckDBInstance } from '@duckdb/node-api'", setup: "const instance = await DuckDBInstance.create()\nconst conn = await instance.connect()", body: "await conn.runAndReadAll(" + unsafeText + ")"},
	{name: "node_sqlite", imports: "import { DatabaseSync } from 'node:sqlite'", setup: "const db = new DatabaseSync(':memory:')", body: "db.prepare(" + unsafeText + ").all()"},
	{name: "local_wrapper", imports: "import { Pool } from 'pg'", setup: "const pool = new Pool()\nasync function run(text) { return pool.query(text) }", body: "await run(" + unsafeText + ")"},
	{name: "imported_wrapper", imports: "import { run } from './db.js'", body: "await run(" + unsafeText + ")",
		files: map[string]string{"db.js": "import oracledb from 'oracledb'\nconst conn = await oracledb.getConnection({})\nexport async function run(text) { return conn.execute(text) }\n"}},
	{name: "batch", imports: "import { createClient } from '@libsql/client'", setup: "const client = createClient({ url: 'file:x' })", body: "await client.executeMultiple('DELETE FROM users WHERE id = ' + id)"},
	{name: "pool_client", imports: "import oracledb from 'oracledb'", setup: "const pool = await oracledb.createPool({})", body: "const conn = await pool.getConnection()\n  await conn.execute(" + unsafeText + ")"},
	{name: "transaction_callback", imports: "import postgres from 'postgres'", setup: "const sql = postgres('postgres://x')", body: "await sql.begin(async (tx) => { await tx.unsafe(" + unsafeText + ") })"},
}

var sqlCallNegatives = []sqlCallForm{
	{name: "logged", imports: "import pino from 'pino'", setup: "const logger = pino()", body: "logger.info(`selected ${id}`)"},
	{name: "returned", body: "const text = " + unsafeText + "\n  if (text === id) return res.json({})"},
	{name: "constant_text", imports: "import oracledb from 'oracledb'", setup: "const conn = await oracledb.getConnection({})", body: "await conn.execute('SELECT * FROM users')"},
	{name: "bound_value", imports: "import oracledb from 'oracledb'", setup: "const conn = await oracledb.getConnection({})", body: "await conn.execute('SELECT * FROM users WHERE id = :1', [id])"},
	{name: "bound_object_value", imports: "import { createClient } from '@libsql/client'", setup: "const client = createClient({ url: 'file:x' })", body: "await client.execute({ sql: 'SELECT * FROM users WHERE id = ?', args: [id] })"},
	{name: "tagged_template", imports: "import postgres from 'postgres'", setup: "const sql = postgres('postgres://x')", body: "await sql`SELECT * FROM users WHERE id = ${id}`"},
	{name: "local_class", setup: "class Store { find(text) { return text.length } }\nconst store = new Store()", body: "store.find(" + unsafeText + ")"},
	{name: "prose_to_package", imports: "import mailer from 'nodemailer'", setup: "const transport = mailer.createTransport({})", body: "await transport.sendMail({ text: `Select a plan for ${id}` })"},
	{name: "reassigned", imports: "import oracledb from 'oracledb'", setup: "let conn = await oracledb.getConnection({})\nconn = { execute: (t) => t }", body: "await conn.execute(" + unsafeText + ")"},
	{name: "shadowed", imports: "import conn from 'oracledb'", body: "{ const conn = { execute: (t) => t }; conn.execute(" + unsafeText + ") }"},
}

func packageSQLUses(r *analysis.AnalysisReport) []analysis.CandidateUse {
	var out []analysis.CandidateUse
	for _, u := range r.Uses {
		if u.Kind == "sql_query_candidate" && u.APIModel != nil && u.APIModel.ID == analysispacks.PackageSQLContract {
			out = append(out, u)
		}
	}
	return out
}

func TestSQLUnknownCall(t *testing.T) {
	for _, f := range sqlCallPositives {
		t.Run(f.name, func(t *testing.T) {
			uses := packageSQLUses(analyzeFiles(t, sqlCallApp(f)))
			if len(uses) != 1 {
				t.Fatalf("want one package SQL record, got %d", len(uses))
			}
			u := uses[0]
			if len(u.Completeness.Evidence["sink_binding"]) < 2 || !strings.Contains(u.Completeness.Evidence["sink_binding"][0].Text, "import") {
				t.Fatalf("binding does not start at an import: %+v", u.Completeness.Evidence["sink_binding"])
			}
			open := 0
			for _, g := range u.Completeness.Blockers {
				if g.Kind == "sink_binding_unverified" {
					open++
				}
			}
			if open != 1 || len(u.Completeness.Blockers) != 1 {
				t.Fatalf("only the binding blocker must stay open for the model: %+v", u.Completeness.Blockers)
			}
			text := false
			for _, d := range u.Dependencies {
				text = text || d.SinkSlot == "sql_text"
			}
			if !text {
				t.Fatalf("no request value in the SQL text slot: %+v", u.Dependencies)
			}
		})
	}
	for _, f := range sqlCallNegatives {
		t.Run("negative_"+f.name, func(t *testing.T) {
			if uses := packageSQLUses(analyzeFiles(t, sqlCallApp(f))); len(uses) != 0 {
				t.Fatalf("recorded as SQL: %+v", uses[0].Sink)
			}
		})
	}
}
