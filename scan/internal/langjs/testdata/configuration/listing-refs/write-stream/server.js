import express from 'express'
import serveIndex from 'serve-index'
import fs from 'node:fs'

const app = express()
const out = fs.createWriteStream('logs/app.log', { flags: 'a' })
app.use('/logs', serveIndex('logs'))
