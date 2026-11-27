import express from 'express'
import serveIndex from 'serve-index'
import path from 'node:path'

const app = express()
app.get('/files/:name', (req, res) => res.sendFile(path.resolve('logs/', req.params.name)))
app.use('/logs', serveIndex('logs'))
