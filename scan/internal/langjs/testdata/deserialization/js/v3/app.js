const express = require('express');
const yaml = require('js-yaml');
const fs = require('fs');

const app = express();

app.post('/js-04', (req, res) => {
  return res.json(yaml.load(req.body.y)); // JS-04
});

app.post('/js-05', (req, res) => {
  return res.json(yaml.safeLoad(req.body.y, { schema: yaml.DEFAULT_FULL_SCHEMA })); // JS-05
});

app.post('/js-06', (req, res) => {
  return res.json(yaml.loadAll(req.body.y)); // JS-06
});

app.post('/js-n2', (req, res) => {
  return res.json(yaml.safeLoad(req.body.y)); // JS-N2
});

app.post('/js-n3', (req, res) => {
  return res.json(yaml.load(req.body.y, { schema: yaml.JSON_SCHEMA })); // JS-N3
});

app.post('/js-n5', (req, res) => {
  return res.json(yaml.load(fs.readFileSync('./config.yml', 'utf8'))); // JS-N5
});

function unresolved(req, res, schema) {
  return res.json(yaml.load(req.body.y, { schema })); // JS-U2
}
app.post('/js-u2', (req, res) => unresolved(req, res, req.body.schema));

app.post('/js-i1', (req, res) => {
  return res.json(yaml.load(req.body.y, { schema: yaml.DEFAULT_FULL_SCHEMA })); // JS-I1
});
