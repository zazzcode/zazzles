import os

from flask import Flask, request

app = Flask(__name__)
UPLOADS = "/srv/uploads"


def secure_filename(name):
    # A local function of the same name is not werkzeug.utils.secure_filename.
    return name


@app.route("/u/fake-sanitizer", methods=["POST"])
def fake_sanitizer():
    upload = request.files["file"]
    upload.save(os.path.join(UPLOADS, secure_filename(upload.filename)))
    return "ok"
