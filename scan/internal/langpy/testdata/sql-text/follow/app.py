import duckdb
import queries
from flask import Flask, request
from helpers import build, label
from queries import BY_NAME, BOUND, Queries

app = Flask(__name__)


@app.route("/join")
def join():
    db = duckdb.connect()
    return str(db.execute(" ".join(["SELECT * FROM users WHERE name = '", request.args.get("n"), "'"])).fetchall())


@app.route("/join-bound")
def join_bound():
    db = duckdb.connect()
    return str(db.execute(" ".join(["SELECT * FROM users", "WHERE name = ?"]), [request.args.get("n")]).fetchall())


@app.route("/parts")
def parts():
    db = duckdb.connect()
    p = ["SELECT * FROM users WHERE name ="]
    p.append("'" + request.args.get("n") + "'")
    return str(db.execute(" ".join(p)).fetchall())


@app.route("/helper")
def helper():
    db = duckdb.connect()
    return str(db.execute(build(request.args.get("n"))).fetchall())


@app.route("/helper-prose")
def helper_prose():
    print(label(request.args.get("n")))
    return "ok"


@app.route("/const")
def const():
    db = duckdb.connect()
    return str(db.execute(BY_NAME.format(request.args.get("n"))).fetchall())


@app.route("/const-bound")
def const_bound():
    db = duckdb.connect()
    return str(db.execute(BOUND, [request.args.get("n")]).fetchall())


@app.route("/module-attr")
def module_attr():
    db = duckdb.connect()
    return str(db.execute(queries.BY_NAME.format(request.args.get("n"))).fetchall())


@app.route("/class-attr")
def class_attr():
    db = duckdb.connect()
    return str(db.execute(Queries.BY_ID + request.args.get("id")).fetchall())


@app.route("/nodeps")
def nodeps():
    db = duckdb.connect()
    return str(db.execute(build("a")).fetchall())
