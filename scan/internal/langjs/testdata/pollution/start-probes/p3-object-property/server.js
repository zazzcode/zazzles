const express = require('express');
const app = express();
app.use(express.json());
const holder = { state: {} };
function setPath(path, value) {
  let cursor = holder.state;
  const parts = path.split('.');
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
}
app.post('/a', (req, res) => { setPath(req.body.path, req.body.value); res.json({ ok: true }); });
