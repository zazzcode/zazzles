import express from 'express'
import serveIndex from 'serve-index'

const app = express()
app.use('/logs', serveIndex('logs'))
