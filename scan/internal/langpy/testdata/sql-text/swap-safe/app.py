import sqlite3
import psycopg2
import pymysql
import mysql.connector
import oracledb
import cx_Oracle
import pyodbc
import pymssql
from sqlalchemy import create_engine, text
from flask import Flask, request, jsonify

app = Flask(__name__)
engine = create_engine("postgresql://db")


def run(conn, name):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (name,))
    return jsonify(cur.fetchall())


@app.route("/sqlite3")
def r_sqlite3():
    conn = sqlite3.connect("a.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/psycopg2")
def r_psycopg2():
    conn = psycopg2.connect("dbname=a")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/pymysql")
def r_pymysql():
    conn = pymysql.connect(host="db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/mysqlconnector")
def r_mysqlconnector():
    conn = mysql.connector.connect(host="db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/oracledb")
def r_oracledb():
    conn = oracledb.connect(user="u", dsn="db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = :1", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/cxoracle")
def r_cxoracle():
    conn = cx_Oracle.connect("u/p@db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = :1", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/pyodbc")
def r_pyodbc():
    conn = pyodbc.connect("DSN=db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/pymssql")
def r_pymssql():
    conn = pymssql.connect(server="db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = %s", (request.args.get("name"),))
    return jsonify(cur.fetchall())


@app.route("/sqlalchemy")
def r_sqlalchemy():
    with engine.connect() as conn:
        rows = conn.execute(text("SELECT * FROM users WHERE name = :name"), {"name": request.args.get("name")})
        return jsonify(list(rows))
