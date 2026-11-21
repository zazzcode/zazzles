const express = require('express');
const yaml = require('js-yaml');
const fs = require('fs');

const app = express();

app.post('/js-n1', (req, res) => {
  return res.json(yaml.load(req.body.y)); // JS-N1
});
