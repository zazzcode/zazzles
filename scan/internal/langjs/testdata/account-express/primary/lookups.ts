import express from 'express'
import { Model, DataTypes } from 'sequelize'
import { expressjwt } from 'express-jwt'
import * as digests from './digests'

class Ticket extends Model {}
Ticket.init({ owner: DataTypes.STRING, secret: DataTypes.STRING }, { sequelize })

const app = express()

app.get('/ticket-owner', async ({ query }, res) => {
  const email = query.email
  const found = await Ticket.findOne({ where: { owner: email } })
  if (found != null) {
    res.json({ ticket: found.id })
  } else {
    res.json({})
  }
})
app.get('/ticket-same', async (req, res) => {
  const found = await Ticket.findOne({ where: { owner: req.query.owner } })
  if (found != null) {
    res.json({ ok: true })
  } else {
    res.json({ ok: true })
  }
})
app.get('/ticket-private', expressjwt({ secret: 'k', algorithms: ['HS256'] }), async (req, res) => {
  const found = await Ticket.findOne({ where: { owner: req.query.owner } })
  if (found) {
    res.json({ ticket: found.id })
  } else {
    res.json({})
  }
})
app.post('/enter', async (req, res) => {
  const hit = await Ticket.findOne({ where: { owner: req.body.owner, secret: digests.fingerprint(req.body.secret) } })
  if (hit) {
    res.json({ token: 't' })
  } else {
    res.status(401).json({})
  }
})
