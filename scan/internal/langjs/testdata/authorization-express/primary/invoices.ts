import express from 'express'
import { Model, DataTypes } from 'sequelize'

class Invoice extends Model {}
Invoice.init({ owner: DataTypes.INTEGER, state: DataTypes.STRING, total: DataTypes.INTEGER }, { sequelize })

const app = express()
const tokens = {}
const claim = (req, res, next) => {
  try {
    req.body.owner = tokens[req.headers.authorization].id
    next()
  } catch {
    res.status(401).json({})
  }
}

app.put('/invoices/:id', (req, res) => { Invoice.update({ state: 'paid' }, { where: { id: req.params.id } }); res.send('ok') })
app.delete('/invoices/:id', (req, res) => { Invoice.destroy({ where: { id: req.params.id } }); res.send('ok') })
app.post('/invoices/:id/bump', (req, res) => { Invoice.increment('total', { where: { id: req.params.id } }); res.send('ok') })
app.post('/invoices/:id/drop', (req, res) => { Invoice.decrement('total', { where: { id: req.params.id } }); res.send('ok') })
app.patch('/invoices/:id', async (req, res) => {
  const row = await Invoice.findByPk(req.params.id)
  await row.update({ state: 'void' })
  res.send('ok')
})
app.delete('/invoices/:id/row', async (req, res) => {
  const row = await Invoice.findByPk(req.params.id)
  await row.destroy()
  res.send('ok')
})
app.put('/invoices/:id/save', async (req, res) => {
  const row = await Invoice.findOne({ where: { id: req.params.id } })
  row.state = 'x'
  await row.save()
  res.send('ok')
})
app.put('/mine/:id', (req, res) => { Invoice.update({ state: 'paid' }, { where: { id: req.params.id, owner: tokens[req.headers.authorization].id } }); res.send('ok') })
app.put('/claimed/:id', claim, (req, res) => { Invoice.update({ state: 'paid' }, { where: { id: req.params.id, owner: req.body.owner } }); res.send('ok') })
app.put('/unclaimed/:id', (req, res) => { Invoice.update({ state: 'paid' }, { where: { id: req.params.id, owner: req.body.owner } }); res.send('ok') })
app.put('/session-row', async (req, res) => {
  const me = tokens[req.headers.authorization]
  const row = await Invoice.findByPk(me.id)
  await row.update({ state: 'seen' })
  res.send('ok')
})
app.post('/reset-all', (req, res) => { Invoice.update({ state: 'new' }, { where: { owner: 7 } }); res.send('ok') })
