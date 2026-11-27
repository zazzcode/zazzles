const express = require('express')
const crypto = require('crypto')
const mongoose = require('mongoose')

// Written from the Mongoose populate documentation: a path with `ref` names
// the model its ObjectId points at.
const captainSchema = new mongoose.Schema({
  handle: String,
  passcode: { type: String, set: (v) => crypto.createHash('md5').update(v).digest('hex') }
})
const Captain = mongoose.model('Captain', captainSchema)

const noteSchema = new mongoose.Schema({
  text: String,
  author: { type: mongoose.Schema.Types.ObjectId, ref: 'Captain' }
})
const Note = mongoose.model('Note', noteSchema)

const tagSchema = new mongoose.Schema({
  label: String,
  place: { type: mongoose.Schema.Types.ObjectId, ref: 'Harbor' }
})
const Tag = mongoose.model('Tag', tagSchema)
const Harbor = mongoose.model('Harbor', new mongoose.Schema({ name: String }))

const app = express()
app.post('/notes', async (req, res) => { await Note.create(req.body); res.send('ok') })
app.post('/notes/new', async (req, res) => { const doc = new Note(req.body); await doc.save(); res.send('ok') })
app.post('/tags', async (req, res) => { await Tag.create(req.body); res.send('ok') })
