const express = require('express');
const app = express();
app.use(express.json());
const store = {};
app.post('/a', (req, res) => { const parts = req.body.path.split('.');
  let cursor = store;
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = req.body.value;
  res.json({ ok: true }); });
