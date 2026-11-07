var express = require('express');
var routes = require('./routes');
var app = express();
app.post('/create', routes.create);
