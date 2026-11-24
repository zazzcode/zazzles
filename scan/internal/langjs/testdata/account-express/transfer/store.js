const crypto = require('node:crypto')
const mongoose = require('mongoose')

const lock = (value) => crypto.createHash('sha1').update(value).digest('hex')
const fileTag = (value) => crypto.createHash('sha1').update(value).digest('hex')

const Visitor = new mongoose.Schema({
  nick: String,
  hash: { type: String, set: (value) => lock(value) },
  note: { type: String },
  token: { type: String, set: (value) => crypto.createHmac('sha256', 'fixed').update(value).digest('hex') }
})

module.exports = { Visitor, tag: (value) => fileTag(value) }
