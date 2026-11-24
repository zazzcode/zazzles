const express = require('express')
const listing = require('serve-index')
const cookieSession = require('cookie-session')
const passport = require('passport')

const site = express()
const insecureCookie = { name: 'sid', keys: ['k'], httpOnly: false }
const cookieOn = { name: 'sid', keys: ['k'], httpOnly: true, secure: true }

site.use('/browse', passport.authenticate('jwt', { session: false }), listing('/srv/data'))
site.use('/static', express.static('/srv/data'))
site.use(cookieSession(insecureCookie))
site.use('/safe', cookieSession(cookieOn))
site.get('/health', (request, response) => { response.send('ok') })
