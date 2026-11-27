const express = require('express')
const mssql = require('mssql')
const oracledb = require('oracledb')

const app = express()

app.get('/oracle', async (req, res) => {
  const conn = await oracledb.getConnection({ user: 'u' })
  const id = String(req.query.id).replace(/'/g, "''")
  const r = await conn.execute("SELECT name FROM users WHERE id = " + id)
  res.json(r.rows)
})
app.get('/mssql', async (req, res) => {
  const p = await mssql.connect('mssql://db')
  const id = String(req.query.id).replace(/'/g, "''")
  const r = await p.request().query(`SELECT name FROM users WHERE id = ${id}`)
  res.json(r.recordset)
})
app.listen(3000)
