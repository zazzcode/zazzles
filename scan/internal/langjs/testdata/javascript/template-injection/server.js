var express = require('express');
var ejs = require('ejs');
var app = express();

app.get('/greet', function (req, res) {
  res.send(ejs.render('<h1>' + req.query.name + '</h1>'));
});

app.get('/safe', function (req, res) {
  res.send(ejs.render('<h1><%= name %></h1>', { name: req.query.name }));
});

app.listen(3000);
