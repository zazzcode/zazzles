import express from 'express'
import serveIndex from 'serve-index'
import path from 'node:path'
import morgan from 'morgan'
import * as rfs from 'rotating-file-stream'

const app = express()
const accessLogStream = rfs.createStream('access.log', { interval: '1d', path: path.resolve('logs/rotated') })
app.use(morgan('combined', { stream: accessLogStream }))
app.use('/logs', serveIndex('logs', { icons: true }))
