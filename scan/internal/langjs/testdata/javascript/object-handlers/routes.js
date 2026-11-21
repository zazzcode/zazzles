// Handlers held by an exported object literal.
exports.chat = {
  get(req, res) {
    res.send('<p>' + req.query.q + '</p>');
  },
  add: function (req, res) {
    res.send('<p>' + req.body.message + '</p>');
  },
  remove: (req, res) => {
    res.send('ok');
  }
};

// A computed key does not name a handler statically.
const verb = 'list';
exports.computed = {
  [verb](req, res) {
    res.send('<p>' + req.query.q + '</p>');
  }
};

// A spread may replace any property.
const base = { list(req, res) { res.send('base'); } };
exports.spread = {
  ...base,
  list(req, res) {
    res.send('<p>' + req.query.q + '</p>');
  }
};

// A later assignment replaces the handler.
exports.patched = {
  list(req, res) {
    res.send('<p>' + req.query.q + '</p>');
  }
};
exports.patched.list = function (req, res) { res.send('patched'); };
