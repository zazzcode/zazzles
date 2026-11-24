const express = require('express')
const eh = require('errorhandler')
const prom = require('prom-client')
const ui = require('swagger-ui-express')

const server = express()
const reg = prom.register
const spec = {}

if (process.env.NODE_ENV === 'development') {
  server.use(eh({ log: false }))
}
server.use(eh())
server.use('/api-spec', ui.serve, ui.setup(spec))
server.get('/stats', async (request, response) => {
  response.send(await reg.metrics())
})
server.get('/runtime', (request, response) => {
  response.json(process.memoryUsage())
})
server.get('/ping', (request, response) => {
  response.send('pong')
})
server.get('/greeting', (request, response) => {
  response.json({ hello: 'world' })
})
