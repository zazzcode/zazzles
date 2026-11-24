import express from 'express'
import serveIndex from 'serve-index'
import { expressjwt } from 'express-jwt'
import session from 'express-session'

const app = express()
const requireToken = expressjwt({ secret: 'k', algorithms: ['HS256'] })
const looseOptions = { secret: 'a', cookie: { httpOnly: false, secure: false } }
const strict = true

app.use('/public-files', serveIndex('files', { icons: true }))
app.use('/private-files', requireToken, serveIndex('private', {}))
app.use('/assets', express.static('assets'))
app.use('/literal', session({ secret: 's', cookie: { httpOnly: false, secure: false } }))
app.use('/variable', session(looseOptions))
app.use('/hardened', session({ secret: 's', cookie: { httpOnly: true, secure: strict } }))
app.get('/', (req, res) => { res.send('ok') })
