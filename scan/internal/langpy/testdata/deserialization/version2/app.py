from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v2')
def py_v2():
    return yaml.load(request.data)  # PY-V2
