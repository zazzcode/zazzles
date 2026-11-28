const express = require('express')
const serveIndex = require('serve-index')
const multer = require('multer')

const app = express()
const upload = multer({ dest: 'uploads/' })
app.use('/uploads', serveIndex('uploads'))
app.post('/upload', upload.single('file'), (req, res) => res.send('ok'))
