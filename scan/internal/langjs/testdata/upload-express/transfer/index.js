const express = require('express')
const multer = require('multer')
const listing = require('serve-index')
const path = require('path')

const site = express()
const suffixes = { 'application/pdf': 'pdf', 'text/plain': 'txt' }
const held = multer()
const kept = multer({
  storage: multer.diskStorage({
    destination: path.join(__dirname, 'shared', 'inbox'),
    filename: function (request, part, done) {
      const stem = path.basename(part.originalname, path.extname(part.originalname))
      const suffix = suffixes[part.mimetype]
      done(null, stem + '-' + Date.now() + '.' + suffix)
    }
  }),
  fileFilter: function (request, part, done) {
    if (!/\.(pdf|txt)$/.test(part.originalname)) {
      return done(null, false)
    }
    done(null, true)
  }
})
const dropped = multer({ dest: 'spool/' })

site.use('/shared', listing(path.join(__dirname, 'shared')))

function accept (request, response) {
  response.end('stored')
}

site.put('/held/one', held.single('report'), accept)
site.put('/held/many', held.array('reports'), accept)
site.put('/held/named', held.fields([{ name: 'summary' }]), accept)
site.put('/held/all', held.any(), accept)
site.put('/kept/one', kept.single('report'), accept)
site.put('/kept/many', kept.array('reports', 2), accept)
site.put('/kept/named', kept.fields([{ name: 'summary' }]), accept)
site.put('/kept/all', kept.any(), accept)
site.put('/dropped', dropped.single('report'), accept)
site.put('/none', accept)
