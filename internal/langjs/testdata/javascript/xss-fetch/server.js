import express from 'express';
const app = express();
app.get('/item', (req, res) => res.json({name: req.query.get}));
app.post('/item', (req, res) => res.json({name: String(req.body.post).replace(/[^\w-]+/g, '')}));
