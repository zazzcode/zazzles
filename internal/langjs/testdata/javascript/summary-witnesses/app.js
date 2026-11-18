const express = require('express')
const { execFileSync } = require('child_process')
const app = express()

function leaf(value) {
  const text = String(value)
  execFileSync('/usr/bin/printf', [text], { shell: false })
  return text
}
function step4(value) { return leaf(value) }
function step3(value) { return step4(value) }
function step2(value) { return step3(value) }
function step1(value) { return step2(value) }
function step0(value) { return step1(value) }

app.get('/left', (req, res) => res.send(step0(req.query.left)))
app.get('/right', (req, res) => res.send(step0(req.query.right)))
