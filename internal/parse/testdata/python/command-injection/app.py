import os
import subprocess
from subprocess import Popen as spawn
from flask import Flask, request

app = Flask(__name__)
runner = subprocess.run


@app.route("/system")
def system_route():
    return str(os.system(request.args.get("cmd", "")))


@app.route("/popen")
def popen_route():
    command = request.args.get("cmd", "")
    stream = os.popen(command, "r")
    return stream.read()


@app.route("/argv")
def argv_route():
    return subprocess.check_output(["ls", request.args.get("dir", "")])


@app.route("/shell-string")
def shell_string():
    return subprocess.run("echo " + request.args.get("m", ""), shell=True)


@app.route("/shell-sequence")
def shell_sequence():
    return subprocess.call(["echo $0", request.args.get("a", "")], shell=True)


@app.route("/keyword")
def keyword_route():
    return spawn(args="echo " + request.args.get("m", ""), shell=True)


@app.route("/executable")
def executable_route():
    return subprocess.run(["ls"], executable=request.args.get("exe", ""))


@app.route("/interpreter")
def interpreter_route():
    return subprocess.run(["/bin/sh", "-c", request.args.get("c", "")])


@app.route("/alias")
def alias_route():
    return runner("echo " + request.args.get("m", ""), shell=True)


@app.route("/constant")
def constant_route():
    os.system("uptime")
    return str(subprocess.run(["ls", "-l"]))


@app.route("/stdio")
def stdio_route():
    return subprocess.run(["cat"], input=request.args.get("x", ""), stdout=subprocess.PIPE)
