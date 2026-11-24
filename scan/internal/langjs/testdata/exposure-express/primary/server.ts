import express from 'express'
import errorhandler from 'errorhandler'
import * as client from 'prom-client'
import swaggerUi from 'swagger-ui-express'

const app = express()
const document = { openapi: '3.0.0' }

app.use(errorhandler())
if (process.env.NODE_ENV !== 'production') {
  app.use(errorhandler())
}
app.use('/docs', swaggerUi.serve, swaggerUi.setup(document))
app.get('/metrics', async (req, res) => {
  res.end(await client.register.metrics())
})
app.get('/metrics-dev', async (req, res) => {
  if (process.env.NODE_ENV !== 'production') {
    res.end(await client.register.metrics())
  }
})
app.get('/env', (req, res) => { res.json(process.env) })
app.get('/mem', (req, res) => { res.json(process.memoryUsage()) })
app.get('/stack', (req, res) => {
  try { JSON.parse(String(req.query.q)) } catch (err) { res.send(err.stack) }
})
app.get('/status', (req, res) => { res.send('ok') })
app.get('/up', (req, res) => { res.json({ up: true }) })
