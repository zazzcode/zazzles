from flask import Flask, request
from jinja2 import Template

app = Flask(__name__)


@app.route("/greet")
def greet():
    name = request.args.get("name")
    content = f"<h1>{name}</h1>"
    return Template(content).render()


@app.route("/safe")
def safe():
    name = request.args.get("name")
    return Template("<h1>{{ name }}</h1>").render(name=name)
