from flask import Flask, request
import yaml

app = Flask(__name__)


@app.post('/py-v5')
def py_v5():
    return yaml.load(request.data)  # PY-V5
