from flask import Flask, request
from myio import open

app = Flask(__name__)


@app.route("/n/shadow-import")
def shadow_import():
    return open(request.args.get("f", ""))
