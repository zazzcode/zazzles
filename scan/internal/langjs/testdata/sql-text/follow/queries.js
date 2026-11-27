const BY_NAME = "SELECT * FROM users WHERE name = '"

function byId(id) {
  return 'SELECT * FROM users WHERE id = ' + id
}

function byIdBound() {
  return 'SELECT * FROM users WHERE id = ?'
}

module.exports = { BY_NAME, byId, byIdBound }
