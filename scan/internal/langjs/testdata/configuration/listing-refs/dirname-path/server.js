import express from 'express'
import serveIndex from 'serve-index'
import path from 'node:path'

const app = express()
const out = path.join(__dirname, 'logs/app.log')
app.use('/logs', serveIndex('logs'))
