import express from 'express'
import finale from 'finale-rest'
import { expressjwt } from 'express-jwt'
import { Model, DataTypes } from 'sequelize'

class Ticket extends Model {}
Ticket.init({ title: DataTypes.STRING, level: DataTypes.STRING }, { sequelize })
class Tag extends Model {}
Tag.init({ label: DataTypes.STRING }, { sequelize })

const app = express()
app.post('/api/Tickets', expressjwt({ secret: 'k', algorithms: ['HS256'] }))
finale.initialize({ app, sequelize })

const tables = [
  { name: 'Ticket', exclude: ['level'], model: Ticket },
  { name: 'Tag', exclude: [], model: Tag }
]
for (const { name, exclude, model } of tables) {
  finale.resource({ model, endpoints: [`/api/${name}s`, `/api/${name}s/:id`], excludeAttributes: exclude, pagination: false })
}

const pick = () => (Math.random() > 0.5 ? Ticket : Tag)
finale.resource({ model: pick(), endpoints: ['/api/Dynamic', '/api/Dynamic/:id'] })
