import express from 'express'
import serveIndex from 'serve-index'

const app = express()
app.use('/files', serveIndex('files'))
app.use('/files-raw', express.static('files'))
app.use('/files-more', serveIndex('./files/'))
