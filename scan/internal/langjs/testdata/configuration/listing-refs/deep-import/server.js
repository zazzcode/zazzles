import express from 'express'
import serveIndex from 'serve-index'
import './lib/first'

const app = express()
app.use('/logs', serveIndex('logs'))
