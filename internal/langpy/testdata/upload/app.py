import os

from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"


@app.route("/raw", methods=["POST"])
def raw():
    doc = request.files["doc"]
    doc.save(os.path.join(UPLOAD_FOLDER, doc.filename))
    return "ok"


@app.route("/declared", methods=["POST"])
def declared():
    doc = request.files["doc"]
    if doc.mimetype == "image/png":
        doc.save(os.path.join(UPLOAD_FOLDER, secure_filename(doc.filename)))
    return "ok"


@app.route("/generated", methods=["POST"])
def generated():
    doc = request.files["doc"]
    doc.save(os.path.join(UPLOAD_FOLDER, "avatar.png"))
    return "ok"
