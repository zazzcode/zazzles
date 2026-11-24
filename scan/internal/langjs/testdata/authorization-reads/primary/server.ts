import express from 'express'
import crypto from 'crypto'
import { Model, DataTypes } from 'sequelize'
import { expressjwt } from 'express-jwt'

class Member extends Model {}
Member.init({
  email: DataTypes.STRING,
  secret: {
    type: DataTypes.STRING,
    set (clear: string) { this.setDataValue('secret', crypto.createHash('md5').update(clear).digest('hex')) }
  }
}, { sequelize })

class Locker extends Model {}
Locker.init({ label: DataTypes.STRING, MemberId: DataTypes.INTEGER }, { sequelize })
Locker.belongsTo(Member, { foreignKey: { name: 'MemberId' } })

class Leaflet extends Model {}
Leaflet.init({ title: DataTypes.STRING }, { sequelize })

const app = express()
const sessions = {}
const signedIn = expressjwt({ secret: 'k', algorithms: ['HS256'] })

app.get('/lockers/:id', async (req, res) => {
  const locker = await Locker.findOne({ where: { id: req.params.id } })
  res.json(locker)
})
app.get('/lockers/:id/key', async (req, res) => {
  const locker = await Locker.findByPk(req.params.id)
  res.json({ data: wrap(locker) })
})
app.get('/lockers', async (req, res) => {
  const id = req.query.id
  const rows = await Locker.findAll({ where: { id } })
  res.send(rows)
})
app.get('/mine/:id', signedIn, async (req, res) => {
  const locker = await Locker.findOne({ where: { id: req.params.id, MemberId: req.auth.id } })
  res.json(locker)
})
app.get('/open/:id', async (req, res) => {
  const locker = await Locker.findOne({ where: { id: req.params.id, MemberId: req.auth.id } })
  res.json(locker)
})
app.get('/leaflets/:id', async (req, res) => {
  const leaflet = await Leaflet.findOne({ where: { id: req.params.id } })
  res.json(leaflet)
})
app.get('/lockers/:id/touch', async (req, res) => {
  const locker = await Locker.findOne({ where: { id: req.params.id } })
  res.json({ status: 'ok' })
})
app.get('/session-locker', async (req, res) => {
  const locker = await Locker.findByPk(sessions[req.headers.authorization].locker)
  res.json(locker)
})
app.get('/shared/:id', async (req, res) => {
  const locker = await Locker.findOne({ where: { id: req.params.id, label: 'shared' } })
  res.json(locker)
})
app.put('/lockers/:id', async (req, res) => {
  const locker = await Locker.findByPk(req.params.id)
  await locker.update({ label: 'renamed' })
  res.json(locker)
})
