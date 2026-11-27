const express = require('express')
const { Pool } = require('pg')
const mysql2 = require('mysql2/promise')
const mysql = require('mysql')
const mssql = require('mssql')
const oracledb = require('oracledb')
const sqlite3 = require('sqlite3')
const Database = require('better-sqlite3')
const knex = require('knex')({ client: 'pg' })
const { Sequelize } = require('sequelize')
const postgres = require('postgres')

const app = express()
app.use(express.json())
const pool = new Pool()
const legacy = mysql.createConnection({ host: 'db' })
const lite = new sqlite3.Database('a.db')
const better = new Database('b.db')
const sequelize = new Sequelize('sqlite::memory:')
const sql = postgres('postgres://db')

app.get('/pg', async (req, res) => {
  const r = await pool.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(r.rows)
})
app.get('/mysql2', async (req, res) => {
  const conn = await mysql2.createConnection({ host: 'db' })
  const [rows] = await conn.query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(rows)
})
app.get('/mysql', (req, res) => {
  legacy.query("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows))
})
app.get('/mssql', async (req, res) => {
  const p = await mssql.connect('mssql://db')
  const r = await p.request().query("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(r.recordset)
})
app.get('/oracle', async (req, res) => {
  const conn = await oracledb.getConnection({ user: 'u' })
  const r = await conn.execute("SELECT * FROM users WHERE name = '" + req.query.name + "'")
  res.json(r.rows)
})
app.get('/sqlite3', (req, res) => {
  lite.all("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, rows) => res.json(rows))
})
app.get('/better', (req, res) => {
  res.json(better.prepare("SELECT * FROM users WHERE name = '" + req.query.name + "'").all())
})
app.get('/knex', async (req, res) => {
  res.json(await knex.raw("SELECT * FROM users WHERE name = '" + req.query.name + "'"))
})
app.get('/sequelize', async (req, res) => {
  res.json(await sequelize.query("SELECT * FROM users WHERE name = '" + req.query.name + "'"))
})
app.get('/postgres', async (req, res) => {
  res.json(await sql.unsafe("SELECT * FROM users WHERE name = '" + req.query.name + "'"))
})
app.listen(3000)
