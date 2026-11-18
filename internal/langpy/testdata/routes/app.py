from flask import Flask, Blueprint
from flask_restx import Api, Resource
from fastapi import FastAPI

app = Flask(__name__)
blueprint = Blueprint('items', __name__, url_prefix='/items')
app.register_blueprint(blueprint)
api = Api(app)
ns = api.namespace('api')
fast = FastAPI()

@app.route('/people/<name>', methods=['GET', 'POST'])
def people(name):
    return name

@blueprint.get('/status')
def status():
    return 'ok'

@ns.route('/entry')
class Entry(Resource):
    def get(self):
        return {}

@fast.post('/records/{record}')
async def records(record: str):
    return record
