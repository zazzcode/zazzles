from flask import Flask, request

app = Flask(__name__)


def open(path):
    # A module-level definition replaces the builtin for every call in this module.
    return path


@app.route("/n/shadow-def")
def shadow_def():
    return open(request.args.get("f", ""))
