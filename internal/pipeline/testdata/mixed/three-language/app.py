import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route('/users', methods=['GET'])
def users():
    conn = sqlite3.connect(':memory:')
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE id = '" + request.args.get('id') + "'")
    return str(cursor.fetchall())
