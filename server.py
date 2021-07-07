from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.status import *
from starlette.types import Scope, Receive, Send
import json
from argparse import ArgumentParser
import os
import uvicorn
import base64
from cryptography.fernet import Fernet
import rsa
import time

from util import *

app = FastAPI()

if __name__ == '__main__':
    parser = ArgumentParser(description='Run the CHAD server.')
    parser.add_argument('--config', default='config.json', help='Path to the CHAD configuration JSON file. Defaults to config.json.')

    args = parser.parse_args()
    with open(args.config, 'r') as f:
        CONFIG = json.load(f)
    os.environ['CHAD-CONFIGURATION'] = args.config
else:
    try:
        with open(os.environ['CHAD-CONFIGURATION'], 'r') as f:
            CONFIG = json.load(f)
    except FileNotFoundError:
        raise ValueError('Bad value for the CHAD configuration path passed to ENVVARS')
    except KeyError:
        raise RuntimeError('The CHAD server is not meant to act as a module.')
    if os.path.exists(default(CONFIG, 'privateKey', 'privKey.pem')) and os.path.exists(default(CONFIG, 'publicKey', 'pubKey.pem')):
        with open(default(CONFIG, 'privateKey', 'privKey.pem'), 'rb') as prk:
            PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(prk.read())
        with open(default(CONFIG, 'publicKey', 'pubKey.pem'), 'rb') as pbk:
            PUBLIC_KEY = rsa.PublicKey.load_pkcs1(pbk.read())
    else:
        PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(512)
        with open(default(CONFIG, 'privateKey', 'privKey.pem'), 'wb') as prk:
            prk.write(PRIVATE_KEY.save_pkcs1())
        with open(default(CONFIG, 'publicKey', 'pubKey.pem'), 'wb') as pbk:
            pbk.write(PUBLIC_KEY.save_pkcs1())

@app.middleware('http')
async def process_request(request: Request, call_next):
    if request.method.lower() == 'post':
        client_public_key = rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(request.headers['X-Public-Key'].encode('utf-8')))
        raw_body_json = await request.json()
        encrypted_data = base64.urlsafe_b64decode(raw_body_json['data'].encode('utf-8'))
        encryption_key = Fernet(rsa.decrypt(base64.urlsafe_b64decode(raw_body_json['key'].encode('utf-8')), PRIVATE_KEY))
        decrypted_data = json.loads(encryption_key.decrypt(encrypted_data).decode('utf-8'))
        request.state.data = decrypted_data

        raw_response: StreamingResponse = await call_next(request)
        

        body = b""
        async for chunk in raw_response.body_iterator:
            body += chunk
        
        new_key = Fernet.generate_key()
        encrypted_body = base64.urlsafe_b64encode(Fernet(new_key).encrypt(body)).decode('utf-8')
        encrypted_key = base64.urlsafe_b64encode(rsa.encrypt(new_key, client_public_key)).decode('utf-8')
        
        final =  Response(
            content=json.dumps({
                'key': encrypted_key,
                'data': encrypted_body
            }),
            status_code=raw_response.status_code,
            media_type=raw_response.media_type
        )
        final.headers['X-Public-Key'] = base64.urlsafe_b64encode(PUBLIC_KEY.save_pkcs1()).decode('utf-8')
        return final
    else:
        resp: Response = await call_next(request)
        resp.headers['X-Public-Key'] = base64.urlsafe_b64encode(PUBLIC_KEY.save_pkcs1()).decode('utf-8')
        return resp

@app.post('/', response_class=JSONResponse)
async def post_root(request: Request):
    return JSONResponse({'request_data': request.state.data, 'timestamp': time.ctime()})

@app.get('/', response_class=JSONResponse)
async def get_root():
    return JSONResponse({'timestamp': time.ctime()})


if __name__ == '__main__':
    uvicorn.run('server:app', host=default(CONFIG, 'host', 'localhost'), port=default(CONFIG, 'port', 88), access_log=default(CONFIG, 'logRequests', False))