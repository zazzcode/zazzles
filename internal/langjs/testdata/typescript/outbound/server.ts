const express = require('express');
const app = express();
const axios = {get: x => x, post: (x,y) => y};
app.post('/outbound', (req, res) => {
  fetch(req.query.url);
  fetch('https://target.invalid/fixed', {method:'POST', body:req.body.value});
  axios.post('https://target.invalid/fixed', req.body.value);
  axios.get(req.query.other);
  res.json({ok:true});
});
app.get('/shadow', (req,res) => {
  const fetch = value => value;
  fetch(req.query.url);
  res.json({ok:true});
});
