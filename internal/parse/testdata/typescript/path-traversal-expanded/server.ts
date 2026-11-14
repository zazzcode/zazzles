import express, { Request, Response, NextFunction } from 'express'
import fs from 'node:fs'
import path from 'node:path'
import unzipper from 'unzipper'
const app = express()
app.set('view engine', 'hbs')
function finish(req: Request, res: Response) { res.end() }
function midRead(req: Request, res: Response, next: NextFunction) { fs.readFileSync(req.query.name); next() }
app.get('/v/middle', midRead, finish)
async function extract(buffer: Buffer) {
  const archive = await unzipper.Open.buffer(buffer)
  for (const item of archive.files) {
    const name = item.path
    fs.createWriteStream('store/' + name)
  }
}
async function midArchive({ file }: Request, res: Response, next: NextFunction) { await extract(file.buffer); next() }
app.post('/v/archive-middle', midArchive, finish)
app.get('/v/layout', (req: Request, res: Response) => { res.render('page', { layout: req.query.layout }) })
app.get('/v/layout-spread', (req: Request, res: Response) => { res.render('page', { ...req.body, title: 'hello' }) })
app.get('/n/layout-overridden', (req: Request, res: Response) => { res.render('page', { ...req.body, layout: false }) })
app.get('/n/layout-constant', (req: Request, res: Response) => { res.render('page', { layout: 'trusted' }) })
import multer from 'multer'
const uploads = multer({ storage: multer.memoryStorage() })
import { exportedArchive } from './upload'
import panel from './panel'
app.post('/v/exported-archive-middle', uploads.single('blob'), exportedArchive, finish)
const filtered = multer({ storage: multer.memoryStorage(), fileFilter: customFilter })
app.post('/u/archive-filter', filtered.single('blob'), exportedArchive, finish)
function configure(app: ReturnType<typeof express>) { app.use('/panel', panel) }
configure(app)
const LAYOUTS = new Set(['basic.hbs', 'wide.hbs'])
app.get('/p/layout-allowlist-alias', (req: Request, res: Response) => {
  const layout = req.query.layout
  const allowed = LAYOUTS.has(layout)
  if (!allowed) return res.status(400).end()
  res.render('page', { layout })
})
app.get('/v/layout-gated-blacklist', (req: Request, res: Response) => {
  if (req.body.layout && process.env.FEATURE_ENABLED) {
    const full = path.resolve(req.body.layout)
    const forbidden = full.includes('private')
    if (!forbidden) res.render('page', { ...req.body })
  }
})

import { tick } from './noise'
app.get('/v/irrelevant-helper-budget', (req: Request, res: Response) => {
 void (() => {
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  tick(0)
  fs.readFileSync(req.query.name)
 })()
})
