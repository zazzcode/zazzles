import pyodbc
import oracledb
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/odbc")
def r_odbc():
    conn = pyodbc.connect("DSN=a")
    cur = conn.cursor()
    v = request.args.get("id").replace("'", "''")
    cur.execute("SELECT name FROM users WHERE id = '" + v + "'")
    return jsonify(cur.fetchall())


@app.route("/oracle")
def r_oracle():
    conn = oracledb.connect(user="u")
    cur = conn.cursor()
    v = request.args.get("id").replace("'", "''")
    cur.execute(f"SELECT name FROM users WHERE id = '{v}'")
    return jsonify(cur.fetchall())
