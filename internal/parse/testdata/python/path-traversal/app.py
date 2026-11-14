import bz2
import gzip
import io
import os
import sqlite3
import tarfile
from pathlib import Path

from flask import Flask, abort, request, send_file, send_from_directory
from werkzeug.utils import secure_filename

from helpers import TRIGGER_MAP, sanitize_name

app = Flask(__name__)
app.config["UPLOAD_FOLDER"] = "/srv/uploads"
ROOT = os.path.abspath("uploads")
ROOT_PATH = Path(ROOT)
ALLOWED = {"report.txt", "notes.txt"}
NAMES = ("report.txt", "notes.txt")


# ---- vulnerable ----------------------------------------------------------

@app.route("/v/open")
def open_route():
    name = request.args.get("f", "")
    with open(name) as handle:
        return handle.read()


@app.route("/v/join")
def join_route():
    # os.path.join returns an absolute later segment alone, replacing the base.
    with open(os.path.join(ROOT, request.args.get("f", ""))) as handle:
        return handle.read()


@app.route("/v/write")
def write_route():
    name = request.args.get("filename")
    text = request.args.get("text")
    with open(name, mode="w") as handle:
        handle.write(text)
    return "ok"


@app.route("/v/io-open")
def io_open_route():
    return io.open(request.args.get("f", "")).read()


@app.route("/v/pathlib-read")
def pathlib_read():
    return (ROOT_PATH / request.args.get("f", "")).read_text()


@app.route("/v/pathlib-bytes")
def pathlib_bytes():
    return Path(request.args.get("f", "")).read_bytes()


@app.route("/v/pathlib-write")
def pathlib_write():
    Path(ROOT, request.args.get("name", "")).write_text(request.args.get("text", ""))
    return "ok"


@app.route("/v/normpath-only")
def normpath_only():
    return open(os.path.normpath(request.args.get("f", ""))).read()


@app.route("/v/try-except")
def try_except():
    try:
        return open(os.path.join(ROOT, request.args.get("f", ""))).read()
    except OSError:
        abort(404)


@app.route("/v/blacklist")
def blacklist():
    name = request.args.get("f", "")
    if ".." in name:
        abort(400)
    return open(os.path.join(ROOT, name)).read()


@app.route("/v/reassigned")
def reassigned():
    name = request.args.get("f", "")
    if name not in ALLOWED:
        abort(404)
    name = request.args.get("g", "")
    return open(os.path.join(ROOT, name)).read()


@app.route("/v/sibling-branch")
def sibling_branch():
    name = request.args.get("f", "")
    if request.args.get("mode") == "strict":
        if name not in ALLOWED:
            abort(404)
    return open(os.path.join(ROOT, name)).read()


def load(name):
    return open(os.path.join(ROOT, name)).read()


@app.route("/v/helper")
def helper_route():
    return load(request.args.get("f", ""))


@app.route("/v/tar")
def tar_open():
    with tarfile.open(request.args.get("f", ""), mode="r:") as archive:
        return archive.getmembers()[0].name


@app.route("/v/bz2")
def bz2_open():
    with bz2.open(request.args.get("f", "")) as handle:
        return handle.read(10)


@app.route("/v/gzip-write")
def gzip_write():
    with gzip.open(filename=request.args.get("f", ""), mode="wb") as handle:
        handle.write(b"x")
    return "ok"


@app.route("/v/upload", methods=["POST"])
def upload_raw():
    # FileStorage.filename is the client-supplied name, unmodified.
    file = request.files["file"]
    filename = file.filename
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))
    return "ok"


@app.route("/v/upload-checked", methods=["POST"])
def upload_checked():
    if "file" not in request.files:
        abort(400)
    file = request.files["file"]
    if file.filename == "":
        abort(400)
    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))
    return "ok"


# ---- protected -----------------------------------------------------------

@app.route("/p/allowlist")
def allowlist():
    name = request.args.get("f", "")
    if name not in ALLOWED:
        abort(404)
    return open(os.path.join(ROOT, name)).read()


@app.route("/p/allowlist-tuple")
def allowlist_tuple():
    name = request.args.get("f", "")
    if name not in NAMES:
        abort(404)
    return open(os.path.join(ROOT, name)).read()


@app.route("/p/prefix-boundary")
def prefix_boundary():
    full = os.path.abspath(os.path.join(ROOT, request.args.get("f", "")))
    if not full.startswith(ROOT + os.sep):
        abort(403)
    return open(full).read()


@app.route("/p/commonpath")
def commonpath_route():
    full = os.path.abspath(os.path.join(ROOT, request.args.get("f", "")))
    if os.path.commonpath([ROOT, full]) != ROOT:
        abort(403)
    return open(full).read()


@app.route("/p/realpath")
def realpath_route():
    full = os.path.realpath(os.path.join(ROOT, request.args.get("f", "")))
    if os.path.commonpath([ROOT, full]) != ROOT:
        abort(403)
    return open(full).read()


@app.route("/p/upload-secure", methods=["POST"])
def upload_secure():
    upload = request.files["file"]
    name = secure_filename(upload.filename)
    upload.save(os.path.join(app.config["UPLOAD_FOLDER"], name))
    return "ok"


def read_checked(file):
    return open(os.path.join(ROOT, file)).read()


@app.route("/p/helper-guard")
def helper_guard():
    name = request.args.get("f", "")
    if name not in ALLOWED:
        abort(404)
    return read_checked(name)


def read_either(file):
    return open(os.path.join(ROOT, file)).read()


@app.route("/u/helper-two-callers")
def helper_two_callers():
    name = request.args.get("f", "")
    if request.args.get("mode") == "strict":
        if name not in ALLOWED:
            abort(404)
        return read_either(name)
    return read_either(name)


# ---- unknown -------------------------------------------------------------

@app.route("/u/prefix-bare")
def prefix_bare():
    full = os.path.abspath(os.path.join(ROOT, request.args.get("f", "")))
    if not full.startswith(ROOT):
        abort(403)
    return open(full).read()


@app.route("/u/missing-helper")
def missing_helper():
    safe = sanitize_name(request.args.get("f", ""))
    return open(os.path.join(ROOT, safe)).read()


@app.route("/u/basename")
def basename_route():
    return open(os.path.join(ROOT, os.path.basename(request.args.get("f", "")))).read()


def read_template(template):
    with open(os.path.join(ROOT, template)) as handle:
        return handle.read()


@app.route("/u/registry-select")
def registry_select():
    # The value is a registry element chosen by equality with the request value:
    # a reconstruction idiom that is not a modeled containment control.
    name = request.args.get("f", "")
    chosen = [key for key in TRIGGER_MAP.keys() if key == name][0]
    return read_template("{}.html".format(chosen))


# ---- no candidate --------------------------------------------------------

@app.route("/n/constant")
def constant_path():
    return open(os.path.join(ROOT, "report.txt")).read()


@app.route("/n/content-only")
def content_only():
    with open(os.path.join(ROOT, "fixed.txt"), "w") as handle:
        handle.write(request.args.get("text", ""))
    return "ok"


@app.route("/n/stored")
def stored_path():
    # The path comes from a stored row; the request value only selects the row.
    cursor = sqlite3.connect("app.db").cursor()
    cursor.execute("SELECT name FROM files WHERE id = ?", (request.args.get("id", ""),))
    row = cursor.fetchone()
    return open(os.path.join(ROOT, row[0])).read()


@app.route("/v/remove")
def remove_route():
    os.remove(os.path.join(ROOT, request.args.get("f", "")))
    return "ok"


@app.route("/v/send-file")
def send_file_route():
    return send_file(request.args.get("f", ""))


@app.route("/p/send-from-dir")
def send_from_dir():
    return send_from_directory(ROOT, request.args.get("f", ""))


@app.route("/v/send-from-dir-dynamic")
def send_from_dir_dynamic():
    return send_from_directory(request.args.get("d", ""), request.args.get("f", ""))


@app.route("/v/send-in-branch")
def send_in_branch():
    name = request.args.get("f", "")
    if name:
        return send_file(os.path.join(ROOT, name))
    return "none"
