from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v3')
def py_v3():
    return yaml.load(request.data)  # PY-V3
