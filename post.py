import requests
import json

def check(data):
    r = requests.get("http://0.0.0.0/posts/check", json=data)
    j = json.loads(r.text)
    print(json.dumps(j, indent = 4))
    return j

