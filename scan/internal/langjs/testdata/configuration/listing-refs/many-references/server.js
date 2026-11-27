import express from 'express'
import serveIndex from 'serve-index'

const app = express()
const sinks = {
  a: 'spool/a.log', b: 'spool/b.log', c: 'spool/c.log', d: 'spool/d.log', e: 'spool/e.log',
  f: 'spool/f.log', g: 'spool/g.log', h: 'spool/h.log', i: 'spool/i.log', j: 'spool/j.log',
}
app.use('/spool', serveIndex('spool'))
