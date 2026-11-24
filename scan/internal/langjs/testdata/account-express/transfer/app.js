const express = require('express')

const web = express()
web.get('/hello', (request, response) => {
  response.send('hi')
})

const mongoose = require('mongoose')
const passport = require('passport')
const Person = mongoose.model('Person', new mongoose.Schema({ mail: String }))

web.get('/exists', async (request, response) => {
  const person = await Person.findOne({ mail: request.query.mail })
  if (!person) {
    return response.status(404).send('no such person')
  }
  response.send('found')
})
web.get('/exists-same', async (request, response) => {
  const person = await Person.findOne({ mail: request.query.mail })
  if (!person) {
    return response.send('done')
  }
  response.send('done')
})
web.get('/exists-private', passport.authenticate('jwt', { session: false }), async (request, response) => {
  const person = await Person.findOne({ mail: request.query.mail })
  if (!person) {
    return response.status(404).send('no such person')
  }
  response.send('found')
})
