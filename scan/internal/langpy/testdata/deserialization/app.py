from flask import Flask, request, abort
import base64
import hashlib
import hmac
import io
import json
import pickle
import pickle as p
from pickle import loads
from pickle import loads as l
import _pickle
import dill
import cloudpickle
import yaml
import jsonpickle
from yaml import UnsafeLoader
import zlib

app = Flask(__name__)
KEY = b"fixture-key"


class Restricted(pickle.Unpickler):
    def find_class(self, module, name):
        raise ValueError("class unavailable")


class Inherited(pickle.Unpickler):
    pass


@app.post('/py-01')
def py_01():
    return pickle.loads(request.data)  # PY-01


@app.post('/py-02')
def py_02():
    return pickle.load(io.BytesIO(request.form['p'].encode()))  # PY-02


@app.post('/py-03')
def py_03():
    return pickle.Unpickler(io.BytesIO(request.data)).load()  # PY-03


@app.post('/py-04')
def py_04():
    return pickle.loads(base64.b64decode(request.cookies.get('p')))  # PY-04


@app.post('/py-05')
def py_05():
    return pickle.loads(zlib.decompress(request.data))  # PY-05


@app.post('/py-06')
def py_06():
    return pickle.loads(request.files['f'].read())  # PY-06


@app.post('/py-07a')
def py_07a():
    return p.loads(request.data)  # PY-07a


@app.post('/py-07b')
def py_07b():
    return loads(request.data)  # PY-07b


@app.post('/py-07c')
def py_07c():
    return l(request.data)  # PY-07c


@app.post('/py-07d')
def py_07d():
    import pickle as local_pickle
    return local_pickle.loads(request.data)  # PY-07d


@app.post('/py-08a')
def py_08a():
    return _pickle.loads(request.data)  # PY-08a


@app.post('/py-08b')
def py_08b():
    return dill.loads(request.data)  # PY-08b


@app.post('/py-08c')
def py_08c():
    return cloudpickle.loads(request.data)  # PY-08c


@app.post('/py-09')
def py_09():
    return yaml.load(request.data, Loader=yaml.UnsafeLoader)  # PY-09


@app.post('/py-10')
def py_10():
    return yaml.load(request.data, yaml.Loader)  # PY-10


@app.post('/py-11a')
def py_11a():
    return yaml.unsafe_load(request.data)  # PY-11a


@app.post('/py-11b')
def py_11b():
    return yaml.load_all(request.data, Loader=yaml.UnsafeLoader)  # PY-11b


@app.post('/py-12')
def py_12():
    return yaml.full_load(request.data)  # PY-12


@app.post('/py-13')
def py_13():
    return jsonpickle.decode(string=request.data, safe=True)  # PY-13


@app.post('/py-n1')
def py_n1():
    return yaml.safe_load(request.data)  # PY-N1


@app.post('/py-n2')
def py_n2():
    return yaml.load(request.data, Loader=yaml.SafeLoader)  # PY-N2


@app.post('/py-n3')
def py_n3():
    return json.loads(request.data)  # PY-N3


@app.post('/py-n4')
def py_n4():
    pickle = request.args.get("module")
    return pickle.loads(request.data)  # PY-N4


@app.post('/py-n5')
def py_n5():
    return pickle.loads(b"")  # PY-N5


@app.post('/py-c1')
def py_c1():
    data = request.data
    sig = request.headers.get("Signature", "")
    if not hmac.compare_digest(hmac.new(KEY, data, "sha256").hexdigest(), sig):
        abort(403)
    return pickle.loads(data)  # PY-C1


@app.post('/py-c2')
def py_c2():
    data = request.data
    digest = request.headers.get("Digest", "")
    if hashlib.sha256(data).hexdigest() != digest:
        abort(403)
    return pickle.loads(data)  # PY-C2


@app.post('/py-c3')
def py_c3():
    return Restricted(io.BytesIO(request.data)).load()  # PY-C3


@app.post('/py-c4')
def py_c4():
    data = request.data
    if not data.startswith(b"\x80"):
        abort(400)
    return pickle.loads(data)  # PY-C4


@app.post('/py-i1')
def py_i1():
    return Inherited(io.BytesIO(request.data)).load()  # PY-I1


@app.post('/py-u1')
def py_u1(loader=None):
    return yaml.load(request.data, Loader=loader)  # PY-U1


@app.post('/py-i2')
def py_i2():
    return yaml.load(stream=request.data, Loader=UnsafeLoader)  # PY-I2
