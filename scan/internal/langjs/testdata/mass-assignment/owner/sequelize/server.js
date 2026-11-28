const express = require('express')
const crypto = require('crypto')
const { Model, DataTypes } = require('sequelize')

// Written from the Sequelize associations documentation: a belongsTo adds a
// foreign key to the source model, named by `foreignKey` or by default.
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
Crate.init({ label: DataTypes.STRING, ownerId: DataTypes.INTEGER }, { sequelize })
Crate.belongsTo(Captain, { foreignKey: 'ownerId' })

class Barrel extends Model {}
Barrel.init({ label: DataTypes.STRING, accountId: DataTypes.INTEGER }, { sequelize })
Barrel.belongsTo(Captain, { foreignKey: { name: 'accountId', allowNull: false } })

class Flag extends Model {}
Flag.init({ label: DataTypes.STRING, skipperId: DataTypes.INTEGER }, { sequelize })
Flag.belongsTo(Captain, { as: 'skipper' })

class Port extends Model {}
Port.init({ place: DataTypes.STRING }, { sequelize })

class Buoy extends Model {}
Buoy.init({ label: DataTypes.STRING, portId: DataTypes.INTEGER }, { sequelize })
Buoy.belongsTo(Port)

class Chart extends Model {}
Chart.init({ title: DataTypes.STRING, userId: DataTypes.INTEGER }, { sequelize })

class Rope extends Model {}
Rope.init({ length: DataTypes.INTEGER, holderId: DataTypes.INTEGER }, { sequelize })
Rope.belongsTo(Captain, { foreignKey: keyName() })

const app = express()
app.post('/ships', async (req, res) => { await Ship.create(req.body); res.send('ok') })
app.post('/crates', async (req, res) => { await Crate.create(req.body); res.send('ok') })
app.post('/barrels', async (req, res) => { await Barrel.create(req.body); res.send('ok') })
app.post('/flags', async (req, res) => { await Flag.create(req.body); res.send('ok') })
app.post('/buoys', async (req, res) => { await Buoy.create(req.body); res.send('ok') })
app.post('/charts', async (req, res) => { await Chart.create(req.body); res.send('ok') })
app.post('/ropes', async (req, res) => { await Rope.create(req.body); res.send('ok') })
