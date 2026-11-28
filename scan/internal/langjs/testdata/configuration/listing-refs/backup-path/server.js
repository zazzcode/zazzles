const express = require('express')
const serveIndex = require('serve-index')
const path = require('path')

const app = express()
const snapshot = { target: 'backups/db.sqlite' }
app.use('/backups', serveIndex('backups'))
