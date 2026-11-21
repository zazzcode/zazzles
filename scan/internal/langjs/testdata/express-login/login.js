const security = {
  login(user) {
    return user
  },
}

function login(req, res) {
  security.login(req.body)
}

function changePassword() {
  return true
}

const tokens = new Map()
tokens.get('token')

app.use(compression())

app.get('/rest/profile', login)

app.post('/rest/user/login', login())

app.get(['/.well-known/security.txt', '/security.txt'], function () {
  return true
})

app.get('/rest/user/change-password', utils.asyncHandler(changePassword()))

app.use('/ftp', ftp)
