const express = require('express');
const serialize = require('node-serialize');
const { unserialize } = require('node-serialize');
const funcster = require('funcster');
const crypto = require('node:crypto');
const KEY = "fixture-key";

const app = express();

app.post('/js-01', (req, res) => {
  return res.json(serialize.unserialize(req.body.x)); // JS-01
});

app.post('/js-02', (req, res) => {
  return res.json(unserialize(Buffer.from(req.cookies.profile, 'base64').toString())); // JS-02
});

app.post('/js-03', (req, res) => {
  return res.json(funcster.deepDeserialize(req.body.f)); // JS-03
});

app.post('/js-07', (req, res) => {
  return res.json(require('node-serialize').unserialize(req.body.x)); // JS-07
});

app.post('/js-n4', (req, res) => {
  return res.json(JSON.parse(req.body.x)); // JS-N4
});

app.post('/js-n6', (req, res) => {
  function unserialize(value) { return value; }
  return res.json(unserialize(req.body.x)); // JS-N6
});

app.post('/js-c1', (req, res) => {
  const x = req.body.x;
  const expected = Buffer.from(req.headers.signature, 'hex');
  if (!crypto.timingSafeEqual(crypto.createHmac('sha256', KEY).update(x).digest(), expected)) return res.sendStatus(403);
  return res.json(serialize.unserialize(x)); // JS-C1
});

app.post('/js-c2', (req, res) => {
  const x = req.body.x;
  if (crypto.createHash('md5').update(x).digest('hex') !== req.headers.digest) return res.sendStatus(403);
  return res.json(serialize.unserialize(x)); // JS-C2
});
