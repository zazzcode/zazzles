import express from 'express'
import * as digests from './digests'

const app = express()

app.post('/signin', (req, res) => {
  sequelize.query(`SELECT * FROM Members WHERE handle = '${req.body.handle}' AND passphrase = '${digests.loginDigest(req.body.passphrase)}'`)
  res.send('ok')
})
app.post('/verify-file', (req, res) => {
  res.send(digests.checksum(req.body.file))
})
