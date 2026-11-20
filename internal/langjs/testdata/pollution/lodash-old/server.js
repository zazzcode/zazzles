const express = require('express');
const lodash = require('lodash');
const app = express();
app.use(express.json());
app.post('/settings', (req, res) => {
  lodash.merge({}, req.body.settings);
  res.end();
});
