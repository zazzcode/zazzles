const express = require('express')
const { Sequelize } = require('sequelize')

const app = express()
const db = new Sequelize('sqlite::memory:')

app.get('/users', async (req, res) => {
  const id = req.query.id
  const rows = await db.query("SELECT name FROM users WHERE id = '" + id + "'")
  res.json(rows)
})

app.listen(3000)
