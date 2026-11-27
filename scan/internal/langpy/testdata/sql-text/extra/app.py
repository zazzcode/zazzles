import logging
import sqlite3
import psycopg2
from flask import Flask, request
import duckdb

app = Flask(__name__)
log = logging.getLogger("x")
Q = "SELECT * FROM users WHERE name = '{}'"


@app.route("/fstring")
def fstring():
    db = duckdb.connect()
    return str(db.execute(f"SELECT * FROM users WHERE name = '{request.args.get('n')}'").fetchall())


@app.route("/percent")
def percent():
    db = duckdb.connect()
    return str(db.execute("SELECT * FROM users WHERE name = '%s'" % request.args.get("n")))


@app.route("/constformat")
def constformat():
    db = duckdb.connect()

    def inner(v):
        return db.sql(Q.format(v))
    return str(inner(request.args.get("n")))


@app.route("/kw")
def kw():
    db = duckdb.connect()
    return str(db.query(sql="SELECT * FROM users WHERE name = '" + request.args.get("n") + "'"))


@app.route("/var")
def var():
    q = "DELETE FROM users WHERE id = " + request.args.get("id")
    q += " AND 1=1"
    return str(duckdb.sql(q))


@app.route("/log")
def logit():
    log.info("SELECT * FROM users WHERE name = '" + request.args.get("n") + "'")
    print("SELECT * FROM users WHERE name = " + request.args.get("n"))
    return "ok"


@app.route("/nodeps")
def nodeps():
    return str(duckdb.sql("SELECT * FROM users WHERE name = 'a'"))


@app.route("/bound")
def bound():
    return str(duckdb.execute("SELECT * FROM users WHERE name = ?", [request.args.get("n")]))


@app.route("/prepared")
def prepared():
    db = duckdb.connect()
    stmt = "SELECT * FROM users WHERE name = ?"
    return str(db.execute(stmt, parameters=[request.args.get("n")]))


@app.route("/contract")
def contract():
    cur = sqlite3.connect("a").cursor()
    cur.execute(query="SELECT * FROM users WHERE name = '" + request.args.get("n") + "'")
    cur.executemany("INSERT INTO t VALUES (?)", [(request.args.get("n"),)])
    return "ok"


@app.route("/stmts")
def stmts():
    db = duckdb.connect()
    db.execute("INSERT INTO t (a) VALUES ('" + request.args.get("n") + "')")
    db.execute("UPDATE t SET a = '" + request.args.get("n") + "' WHERE id = 1")
    db.execute("CREATE TABLE " + request.args.get("n") + " (a int)")
    db.execute("DROP TABLE " + request.args.get("n"))
    db.execute("PRAGMA table_info(" + request.args.get("n") + ")")
    db.execute("SELECT 1; " + request.args.get("n"))
    return "ok"
