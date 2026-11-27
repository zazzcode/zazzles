import express from 'express'
import serveIndex from 'serve-index'

const app = express()
const sample = { target: 'logs/x' }
app.use('/logs', serveIndex('logs'))
