const express = require('express')
const { Pool } = require('pg')
const postgres = require('postgres')
const { PrismaClient } = require('@prisma/client')
const SQL = require('sql-template-strings')
const mysql2 = require('mysql2/promise')

const app = express()
const pool = new Pool()
const sql = postgres('postgres://db')
const prisma = new PrismaClient()

function raw(strings, ...values) {
  return strings.reduce((out, s, i) => out + s + (i < values.length ? values[i] : ''), '')
}

function bound(strings, ...values) {
  return { text: strings.reduce((out, s, i) => out + s + (i < values.length ? '$' + (i + 1) : ''), ''), values }
}

function run(strings, ...values) {
  return pool.query(String.raw({ raw: strings }, ...values))
}

app.get('/library-tag', async (req, res) => {
  res.json(await sql`SELECT * FROM users WHERE id = ${req.query.id}`)
})
app.get('/concat-tag', async (req, res) => {
  const r = await pool.query(raw`SELECT * FROM users WHERE name = '${req.query.name}'`)
  res.json(r.rows)
})
app.get('/bound-tag', async (req, res) => {
  const r = await pool.query(bound`SELECT * FROM users WHERE id = ${req.query.id}`)
  res.json(r.rows)
})
app.get('/concat-run', async (req, res) => {
  const r = await run`DELETE FROM users WHERE id = ${req.query.id}`
  res.json(r.rowCount)
})
app.get('/prisma-tag', async (req, res) => {
  res.json(await prisma.$queryRaw`SELECT * FROM users WHERE name = ${req.query.name}`)
})
app.get('/template-strings', async (req, res) => {
  const conn = await mysql2.createConnection({ host: 'db' })
  const [rows] = await conn.query(SQL`SELECT * FROM users WHERE name = ${req.query.name}`)
  res.json(rows)
})
app.listen(3000)
