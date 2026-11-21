from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v4')
def py_v4():
    return yaml.load(request.data)  # PY-V4
