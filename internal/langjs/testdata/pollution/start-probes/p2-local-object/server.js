const express = require('express');
const app = express();
app.use(express.json());
function build(path, value) {
  const out = {};
  let cursor = out;
  const parts = path.split('.');
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
  return out;
}
app.post('/a', (req, res) => { res.json(build(req.body.path, req.body.value)); });
