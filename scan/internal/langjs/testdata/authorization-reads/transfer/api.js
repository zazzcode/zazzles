const express = require('express')
const mongoose = require('mongoose')
const crypto = require('crypto')
const passport = require('passport')

const personSchema = new mongoose.Schema({
  handle: String,
  passphrase: { type: String, set: (plain) => crypto.createHash('sha1').update(plain).digest('hex') }
})
const Person = mongoose.model('Person', personSchema)

const diarySchema = new mongoose.Schema({
  text: String,
  writer: { type: mongoose.Schema.Types.ObjectId, ref: 'Person' }
})
const Diary = mongoose.model('Diary', diarySchema)

const posterSchema = new mongoose.Schema({ headline: String })
const Poster = mongoose.model('Poster', posterSchema)

const site = express()
const live = {}

site.get('/diaries/:ref', (request, response) => {
  Diary.findById(request.params.ref).then((entry) => {
    response.json(entry)
  })
})
site.get('/diary', (request, response) => {
  Diary.findOne({ _id: request.query.ref }).then(function (entry) {
    response.render('diary', { entry })
  })
})
site.get('/own/:ref', passport.authenticate('jwt', { session: false }), (request, response) => {
  Diary.findOne({ _id: request.params.ref, writer: request.user.id }).then((entry) => {
    response.json(entry)
  })
})
site.get('/posters/:ref', (request, response) => {
  Poster.findById(request.params.ref).then((poster) => {
    response.json(poster)
  })
})
site.get('/diaries/:ref/ping', (request, response) => {
  Diary.findById(request.params.ref).then((entry) => {
    response.json({ ok: true })
  })
})
site.get('/current-diary', (request, response) => {
  Diary.findById(live[request.headers.authorization].diary).then((entry) => {
    response.json(entry)
  })
})
site.get('/checked/:ref', passport.authenticate('jwt', { session: false }), (request, response) => {
  Diary.findById(request.params.ref).then((entry) => {
    if (String(entry.writer) !== request.user.id) {
      response.status(403).end()
      return
    }
    response.json(entry)
  })
})
