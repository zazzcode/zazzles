import express from 'express'
import serveIndex from 'serve-index'

const app = express()
const mirror = { copy: 'logs-public/a.txt' }
app.use('/logs', serveIndex('logs'))
