import express from 'express'
import { Model, DataTypes } from 'sequelize'

class Profile extends Model {}
Profile.init({ handle: DataTypes.STRING, role: DataTypes.STRING, balance: DataTypes.INTEGER }, { sequelize })

const app = express()

app.post('/p/create', async (req, res) => { await Profile.create(req.body); res.send('ok') })
app.post('/p/build', async (req, res) => { const row = Profile.build(req.body); await row.save(); res.send('ok') })
app.post('/p/bulk', async (req, res) => { await Profile.bulkCreate(req.body); res.send('ok') })
app.put('/p/:id', async (req, res) => { await Profile.update(req.body, { where: { id: req.params.id } }); res.send('ok') })
app.patch('/p/:id', async (req, res) => {
  const row = await Profile.findByPk(req.params.id)
  await row.update(req.body)
  res.send('ok')
})
app.patch('/p/:id/set', async (req, res) => {
  const row = await Profile.findByPk(req.params.id)
  row.set(req.body)
  await row.save()
  res.send('ok')
})
app.post('/p/assign', async (req, res) => {
  const row = await Profile.findByPk(req.params.id)
  Object.assign(row, req.body)
  await row.save()
  res.send('ok')
})
app.post('/p/spread', async (req, res) => { await Profile.create({ ...req.body }); res.send('ok') })
app.post('/p/fields', async (req, res) => { await Profile.create(req.body, { fields: ['handle'] }); res.send('ok') })
app.post('/p/named', async (req, res) => { await Profile.create({ handle: req.body.handle }); res.send('ok') })
