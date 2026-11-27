const express = require('express')
const { BY_NAME, byId, byIdBound } = require('./queries')

const app = express()
const prepared = db.prepare('SELECT * FROM users WHERE id = ?')

function sql(strings, ...values) {
  return { text: strings.join('?'), values }
}

function build(id) {
  if (!id) {
    return 'nothing to run'
  }
  return 'SELECT * FROM users WHERE id = ' + id
}

// join: text, bound twin, no request data, prose
app.get('/join', async (req, res) => {
  await db.run(['SELECT * FROM users', "WHERE name = '" + req.query.name + "'"].join(' '))
})
app.get('/join-bound', async (req, res) => {
  await db.run(['SELECT * FROM users', 'WHERE name = ?'].join(' '), [req.query.name])
})
app.get('/join-none', async (req, res) => {
  await db.run(['SELECT * FROM users', 'WHERE id = 1'].join(' '))
  res.send(['Select a file', 'from the list', req.query.n].join(' '))
})

// helper: text, bound twin, two returns, no request data
app.get('/helper', async (req, res) => {
  await db.run(build(req.query.id))
})
app.get('/helper-bound', async (req, res) => {
  await db.run(byIdBound(), [req.query.id])
})
app.get('/helper-other-file', async (req, res) => {
  await db.run(byId(req.query.id))
})
app.get('/helper-none', async (req, res) => {
  await db.run(build(1))
})

// another module's constant
app.get('/constant', async (req, res) => {
  await db.run(BY_NAME + req.query.name + "'")
})

// a statement prepared apart from the value
app.get('/prepared', async (req, res) => {
  const st = db.prepare('SELECT * FROM users WHERE id = ?')
  res.json(st.get(req.query.id))
  st.all(req.query.other)
})
app.get('/prepared-module', async (req, res) => {
  res.json(prepared.get(req.query.id))
})
app.get('/prepared-none', async (req, res) => {
  const st = db.prepare('SELECT * FROM users WHERE id = ?')
  res.json(st.get(1))
})

// tagged templates
app.get('/tag', async (req, res) => {
  await sql`SELECT * FROM users WHERE id = ${req.query.id}`
})
app.get('/tag-argument', async (req, res) => {
  await db.run(sql`SELECT * FROM users WHERE name = '${req.query.name}'`)
})
app.get('/tag-none', async (req, res) => {
  await sql`SELECT * FROM users WHERE id = ${1}`
  await sql`hello ${req.query.id}`
})
