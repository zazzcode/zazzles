from flask import Flask, request
import requests, httpx
import urllib.request
app = Flask(__name__)
@app.post('/outbound')
def outbound():
    requests.post('https://target.invalid/fixed', data=request.json)
    requests.request('GET', request.args.get('url'))
    httpx.get(url=request.args.get('other'))
    urllib.request.urlopen(request.args.get('third'))
    response = requests.get('https://target.invalid/fixed')
    requests.post('https://target.invalid/fixed', data=response.text)
    requests.get(response.text)
    return 'ok'
