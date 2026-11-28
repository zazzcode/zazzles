import express from 'express'
import serveIndex from 'serve-index'
import path from 'node:path'

const app = express()
const a = '/var/logs/app.log'
const b = path.join('/logs', 'app.log')
app.use('/logs', serveIndex('logs'))
