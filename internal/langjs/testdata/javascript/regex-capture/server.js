var express = require('express');
var exec = require('child_process').exec;
var app = express();

// The capture admits any character after "img:http", including shell syntax.
app.post('/thumbnail', function (req, res) {
  var source = req.body.source;
  var imageRe = /^img:(http.*)$/;
  if (typeof source == 'string' && source.match(imageRe)) {
    exec('identify ' + source.match(imageRe)[1]);
  }
  res.send('ok');
});

// The capture admits only a host alphabet; its adequacy is the model's call.
app.post('/ping', function (req, res) {
  var target = req.body.target;
  var hostRe = /^host:([a-z0-9.-]+)$/;
  if (hostRe.test(target)) {
    var host = hostRe.exec(target)[1];
    exec('ping -c 1 ' + host);
  }
  res.send('ok');
});

// Another control beside the match test keeps the path guarded.
app.post('/limited', function (req, res) {
  var source = req.body.source;
  var imageRe = /^img:(http.*)$/;
  if (source.match(imageRe) && source.length < 64) {
    exec('identify ' + source.match(imageRe)[1]);
  }
  res.send('ok');
});
