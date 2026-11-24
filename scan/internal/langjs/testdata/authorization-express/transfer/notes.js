const express = require('express')
const MarsDB = require('marsdb')

const memo = new MarsDB.Collection('memo')
const site = express()

site.post('/memo/edit', (request, response) => {
  memo.update({ _id: request.body.ref }, { $set: { text: request.body.text } })
  response.send('saved')
})
site.post('/memo/drop', (request, response) => {
  memo.remove({ _id: request.body.ref })
  response.send('gone')
})
site.post('/memo/purge', (request, response) => {
  memo.remove({ kind: 'draft' })
  response.send('gone')
})
