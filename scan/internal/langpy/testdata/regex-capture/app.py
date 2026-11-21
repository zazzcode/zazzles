import re
import subprocess

from flask import Flask, request

app = Flask(__name__)


@app.route("/thumbnail")
def thumbnail():
    # The capture admits any character after "img:http", including shell syntax.
    m = re.match(r"img:(http.*)", request.args.get("source"))
    if m:
        subprocess.run("identify " + m.group(1), shell=True)
    return "ok"


@app.route("/ping")
def ping():
    # The capture admits only a host alphabet; its adequacy is the model's call.
    m = re.fullmatch(r"host:([a-z0-9.-]+)", request.args.get("target"))
    if m:
        subprocess.run("ping -c 1 " + m.group(1), shell=True)
    return "ok"


@app.route("/limited")
def limited():
    # Another control beside the match test keeps the path guarded.
    source = request.args.get("source")
    m = re.match(r"img:(http.*)", source)
    if m and len(source) < 64:
        subprocess.run("identify " + m.group(1), shell=True)
    return "ok"
