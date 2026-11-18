import express from 'express';
import escapeHtml from 'escape-html';
const app = express();
function factory(encode) {
  return (req, res) => res.send('<p>' + (encode ? escapeHtml(req.query.q) : req.query.q) + '</p>');
}
const registrations = [['/raw', false], ['/encoded', true]];
for (const [path, encode] of registrations) {
  app.get(path, factory(encode));
}
app.get('/unknown', factory(runtimeMode));
app.get('/zero', (req, res) => res.json({ok: true}));
