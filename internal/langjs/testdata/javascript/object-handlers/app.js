var express = require('express');
var routes = require('./routes');
var app = express();

app.get('/chat', routes.chat.get);
app.put('/chat', routes.chat.add);
app.delete('/chat', routes.chat.remove);
app.get('/computed', routes.computed.list);
app.get('/spread', routes.spread.list);
app.get('/patched', routes.patched.list);

app.listen(3000);
