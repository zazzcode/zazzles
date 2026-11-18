# Independent scanner controls; not a modified VulnPy source excerpt.
from flask import Flask, request
from markupsafe import escape
import sqlite3

app = Flask(__name__)


def register(path, mode):
    @app.get(path)
    def handler():
        value = request.args.get("q")
        if mode == "encoded":
            return "<p>" + escape(value) + "</p>"
        if mode == "unknown":
            return "<p>" + custom(value) + "</p>"
        return "<p>" + value + "</p>"


register("/control/raw", "raw")
register("/control/encoded", "encoded")
register("/control/unknown", "unknown")


def sql_register(path, bound):
    @app.get(path)
    def handler():
        user_input = request.args.get("q")
        connection = sqlite3.connect(":memory:")
        cursor = connection.cursor()
        if bound == "yes":
            cursor.execute("SELECT ?", (user_input,))
        else:
            cursor.execute("SELECT '{}'".format(user_input))
        return "done"


sql_register("/control/sql-bound", "yes")
sql_register("/control/sql-raw", "no")
