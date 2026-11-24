const express = require('express')
const mongoose = require('mongoose')

const memberSchema = new mongoose.Schema({ nick: String, rank: String })
const Member = mongoose.model('Member', memberSchema)
const web = express()

web.post('/m/new', async (request, response) => {
  const doc = new Member(request.body)
  await doc.save()
  response.send('ok')
})
web.post('/m/make', async (request, response) => { await Member.create(request.body); response.send('ok') })
web.put('/m/:id', async (request, response) => { await Member.findByIdAndUpdate(request.params.id, request.body); response.send('ok') })
web.put('/m/:id/flat', async (request, response) => { await Member.updateOne({ _id: request.params.id }, request.body); response.send('ok') })
web.post('/m/named', async (request, response) => { await Member.create({ nick: request.body.nick }); response.send('ok') })
