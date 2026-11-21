const express = require('express');
const app = express();
app.use(express.json());
class Settings {
  constructor() { this.state = {}; }
  set(path, value) {
    let cursor = this.state;
  const parts = path.split('.');
  for (let i = 0; i < parts.length - 1; i++) cursor = cursor[parts[i]];
  cursor[parts[parts.length - 1]] = value;
  }
}
const settings = new Settings();
app.post('/a', (req, res) => { settings.set(req.body.path, req.body.value); res.json({ ok: true }); });
