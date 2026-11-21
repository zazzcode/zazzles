from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v6')
def py_v6():
    return yaml.load(request.data)  # PY-V6
