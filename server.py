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

if __name__ == '__main__': # Get args on program initial load
    parser = ArgumentParser(description='Run the CHAD server.')
    parser.add_argument('--config', default='config.json', help='Path to the CHAD configuration JSON file. Defaults to config.json.')

    args = parser.parse_args()
    with open(args.config, 'r') as f:
        CONFIG = json.load(f)
    os.environ['CHAD-CONFIGURATION'] = args.config # Pass config path to ENV for uvicorn run
else: # Run when running through uvicorn
    try:
        with open(os.environ['CHAD-CONFIGURATION'], 'r') as f:
            CONFIG = json.load(f) # Load configuration
    except FileNotFoundError:
        raise ValueError('Bad value for the CHAD configuration path passed to ENVVARS')
    except KeyError:
        raise RuntimeError('The CHAD server is not meant to act as a module.')
    if os.path.exists(default(CONFIG, 'privateKey', 'privKey.pem')) and os.path.exists(default(CONFIG, 'publicKey', 'pubKey.pem')): # Load saved RSA keys
        with open(default(CONFIG, 'privateKey', 'privKey.pem'), 'rb') as prk:
            PRIVATE_KEY = rsa.PrivateKey.load_pkcs1(prk.read())
        with open(default(CONFIG, 'publicKey', 'pubKey.pem'), 'rb') as pbk:
            PUBLIC_KEY = rsa.PublicKey.load_pkcs1(pbk.read())
    else: # Generate and save new RSA keys
        PUBLIC_KEY, PRIVATE_KEY = rsa.newkeys(512)
        with open(default(CONFIG, 'privateKey', 'privKey.pem'), 'wb') as prk:
            prk.write(PRIVATE_KEY.save_pkcs1())
        with open(default(CONFIG, 'publicKey', 'pubKey.pem'), 'wb') as pbk:
            pbk.write(PUBLIC_KEY.save_pkcs1())

@app.middleware('http')
async def process_request(request: Request, call_next): # decrypt POST requests
    if request.method.lower() == 'post':
        client_public_key = rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(request.headers['X-Public-Key'].encode('utf-8'))) # Get client public key from headers
        raw_body_json = await request.json()
        encrypted_data = base64.urlsafe_b64decode(raw_body_json['data'].encode('utf-8')) # Get encrypted data
        encryption_key = Fernet(rsa.decrypt(base64.urlsafe_b64decode(raw_body_json['key'].encode('utf-8')), PRIVATE_KEY)) # Get RSA-encrypted Fernet key
        decrypted_data = json.loads(encryption_key.decrypt(encrypted_data).decode('utf-8')) # Decrypt data
        request.state.data = decrypted_data

        raw_response: StreamingResponse = await call_next(request) # Call endpoint
        

        body = b""
        async for chunk in raw_response.body_iterator: # Get response body
            body += chunk
        
        new_key = Fernet.generate_key() # Generate new key
        encrypted_body = base64.urlsafe_b64encode(Fernet(new_key).encrypt(body)).decode('utf-8') # Encrypt body
        encrypted_key = base64.urlsafe_b64encode(rsa.encrypt(new_key, client_public_key)).decode('utf-8') # Encrypt Fernet key
        
        final = Response( # Assemble new response object
            content=json.dumps({
                'key': encrypted_key,
                'data': encrypted_body
            }),
            status_code=raw_response.status_code,
            media_type=raw_response.media_type
        )
        final.headers['X-Public-Key'] = base64.urlsafe_b64encode(PUBLIC_KEY.save_pkcs1()).decode('utf-8') # Set public key header
        return final
    else: # Do not process GET requests
        resp: Response = await call_next(request)
        print(request.headers.keys())
        if 'x-public-key' in request.headers.keys(): # Encrypt return data if the request headers include a public key
            client_public_key = rsa.PublicKey.load_pkcs1(base64.urlsafe_b64decode(request.headers['X-Public-Key'].encode('utf-8')))
            body = b""
            async for chunk in resp.body_iterator: # Get response body
                body += chunk
            
            new_key = Fernet.generate_key() # Generate new key
            encrypted_body = base64.urlsafe_b64encode(Fernet(new_key).encrypt(body)).decode('utf-8') # Encrypt body
            encrypted_key = base64.urlsafe_b64encode(rsa.encrypt(new_key, client_public_key)).decode('utf-8') # Encrypt Fernet key
            resp = Response( # Assemble new response object
                content=json.dumps({
                    'key': encrypted_key,
                    'data': encrypted_body
                }),
                status_code=resp.status_code,
                media_type=resp.media_type
            )
        resp.headers['X-Public-Key'] = base64.urlsafe_b64encode(PUBLIC_KEY.save_pkcs1()).decode('utf-8') # Set public key header
        return resp

@app.post('/', response_class=JSONResponse) # Post @ root, used for testing
async def post_root(request: Request):
    return JSONResponse({'request_data': request.state.data, 'timestamp': time.ctime()})

@app.get('/', response_class=JSONResponse) # Get @ root, used for testing and getting the server's public key.
async def get_root(request: Request):
    return JSONResponse({'timestamp': time.ctime(), 'parameters': request.query_params._dict})


if __name__ == '__main__':
    uvicorn.run('server:app', host=default(CONFIG, 'host', 'localhost'), port=default(CONFIG, 'port', 88), access_log=default(CONFIG, 'logRequests', False))