const express = require('express')
const crypto = require('crypto')
const { Model, DataTypes } = require('sequelize')

class Captain extends Model {}
Captain.init({
  handle: DataTypes.STRING,
  passcode: {
    type: DataTypes.STRING,
    set (clear) { this.setDataValue('passcode', crypto.createHash('md5').update(clear).digest('hex')) }
  }
}, { sequelize })

class Ship extends Model {}
Ship.init({ name: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Ship.belongsTo(Captain)

class Crate extends Model {}
Crate.init({ label: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Crate.belongsTo(Captain)

class Barrel extends Model {}
Barrel.init({ label: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Barrel.belongsTo(Captain)

class Keg extends Model {}
Keg.init({ label: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Keg.belongsTo(Captain)

class Sack extends Model {}
Sack.init({ label: DataTypes.STRING, captainId: DataTypes.INTEGER }, { sequelize })
Sack.belongsTo(Captain)

const app = express()

const stampOwner = (req, res, next) => {
  req.body.captainId = req.session.captain
  next()
}

// A stage in the entry's own chain.
app.post('/ships', stampOwner, async (req, res) => { await Ship.create(req.body); res.send('ok') })

// An earlier matching registration that forwards.
app.all('/crates', (req, res, next) => {
  req.body.captainId = req.session.captain
  next()
})
app.post('/crates', async (req, res) => { await Crate.create(req.body); res.send('ok') })

// An assignment in the handler before the write.
app.post('/barrels', async (req, res) => {
  req.body.captainId = req.session.captain
  await Barrel.create(req.body)
  res.send('ok')
})

// A conditional assignment is not followed: the attribute stays in.
app.post('/kegs', async (req, res) => {
  if (req.session.captain) {
    req.body.captainId = req.session.captain
  }
  await Keg.create(req.body)
  res.send('ok')
})

// An assignment after the write does not guard it.
app.post('/sacks', async (req, res) => {
  await Sack.create(req.body)
  req.body.captainId = req.session.captain
  res.send('ok')
})
