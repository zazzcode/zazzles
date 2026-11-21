from flask import Flask, request

app = Flask(__name__)


@app.route("/n/shadow-local")
def shadow_local():
    open = lambda p: p
    return open(request.args.get("f", ""))
