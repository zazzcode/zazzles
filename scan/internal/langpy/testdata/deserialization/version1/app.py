from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v1')
def py_v1():
    return yaml.load(request.data)  # PY-V1
