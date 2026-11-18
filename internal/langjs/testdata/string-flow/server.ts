import express from 'express'
import { login as authenticate } from './handler'
const app = express()
app.post('/login', authenticate())
