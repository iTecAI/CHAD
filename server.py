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
import random
import hashlib
import re
import traceback

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
    
    if os.path.exists(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'))): # Check that database root exists. If not, create it.
        if not os.path.exists(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), '.links')):
            with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), '.links'), 'w') as f:
                f.write(json.dumps({
                    "aliases": {},
                    "links": {}
                }))
    else:
        try:
            os.makedirs(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/')), exist_ok=True)
            with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), '.links'), 'w') as f:
                f.write(json.dumps({
                    "aliases": {},
                    "links": {}
                }))
        except:
            raise ValueError(f"Bad value for databaseRoot: {str(default(CONFIG, 'databaseRoot', 'root'))}")
    
    with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), '.links'), 'r') as f:
        LINK_CACHE = json.load(f)
    
    LOCK = []

def check_lock(lid):
    while lid in LOCK:
        pass

def _save_cache(cache):
    with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), '.links'), 'w') as f:
        json.dump(cache, f)

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
    return JSONResponse({'timestamp': time.ctime(), 'parameters': request.query_params._dict, 'link_cache': LINK_CACHE})

@app.post('/doc/new') # content[r], mediaType[r], longId[o], shortId[o], documentPath[o]
async def post_doc_new(request: Request, response: Response): # Create a new document/object
    global LINK_CACHE, LOCK
    data: dict = request.state.data

    # Generate IDs
    if 'longId' in data.keys():
        longId = str(data['longId'])
    else:
        longId = base64.urlsafe_b64encode(
            hashlib.sha256(
                str(time.time()+random.random()).encode('utf-8')
            ).hexdigest().encode('utf-8')
        ).decode('utf-8').strip('=')
    if 'shortId' in data.keys():
        shortId = base64.urlsafe_b64encode(str(data['shortId']).encode('utf-8')).decode('utf-8')
    else:
        shortId = base64.urlsafe_b64encode(''.join([random.choice(longId) for _ in range(default(CONFIG, 'aliasLength', 12))]).encode('utf-8')).decode('utf-8')
    
    # Check required & default body contents
    if not 'content' in data.keys():
        response.status_code = HTTP_400_BAD_REQUEST
        return {'result': 'Must include "content" key in request data.'}
    if not 'mediaType' in data.keys():
        response.status_code = HTTP_400_BAD_REQUEST
        return {'result': 'Must include "mediaType" key in request data.'}
    if not 'documentPath' in data.keys():
        data['documentPath'] = ''
    
    # Check for valid MIME type
    if len(data['mediaType']) > 0 and re.fullmatch('.{1,}/.{1,}', data['mediaType']) and data['mediaType'].split('/')[0].lower() in MIME_REGISTRIES:
        registry = data['mediaType'].split('/')[0].lower()
        datatype = data['mediaType'].split('/')[1].lower()

        # Determine file extension
        if 'extension' in data.keys():
            extension = data['extension']
        elif datatype == 'plain':
            extension = 'txt'
        else:
            extension = datatype+''
        
        # Build paths
        real_path = longId + '.' + extension
        if len(data['documentPath']) == 0:
            canonical_fullpath = longId + ''
            canonical_shortpath = shortId + ''
        else:
            canonical_fullpath = data['documentPath'] + '.' + longId
            canonical_shortpath = data['documentPath'] + '.' + shortId
        
        check_lock(longId)
        LOCK.append(longId)
        
        try:
            # Add the link to the cache
            LINK_CACHE['links'][longId] = {
                'mediaType': {
                    'registry': registry,
                    'datatype': datatype,
                    'mime': data['mediaType'].lower(),
                    'extension': extension
                },
                'aliases': [canonical_shortpath, canonical_fullpath],
                'path': data['documentPath'],
                'filePath': real_path,
                'ids': {
                    'long': longId,
                    'short': shortId
                }
            }

            # Set aliases
            LINK_CACHE['aliases'][canonical_shortpath] = longId + ''
            LINK_CACHE['aliases'][canonical_fullpath] = longId + ''
            _save_cache(LINK_CACHE)

            # Save document
            if datatype == 'json':
                if not type(data['content']) in [dict, str]:
                    response.status_code = HTTP_400_BAD_REQUEST
                    return {'result': f'JSON content should be in string or mapping form. Content recieved was in form "{str(type(data["content"]))}" instead.'}
                with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), real_path), 'w') as f:
                    if type(data['content']) == dict:
                        json.dump(data['content'], f)
                    elif type(data['content']) == str:
                        f.write(data['content'])
            else:
                if re.fullmatch('data:.{1,}/.{1,};base64,.{0,}',data['content']):
                    content = base64.urlsafe_b64decode(data['content'].split(',')[1].encode('utf-8'))
                else:
                    content = data['content'].encode('utf-8')
                with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), real_path), 'wb') as f:
                    f.write(content)
        except:
            LOCK.remove(longId)
            response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
            return {'result': f'Unexpected error occurred: {traceback.format_exc()}'}
            
        LOCK.remove(longId)
        
        return {'result': 'success', 'longId': longId, 'shortId': shortId, 'aliases': LINK_CACHE['links'][longId]['aliases']}
            
    else:
        response.status_code = HTTP_400_BAD_REQUEST
        return {'result': f'mediaType key "{data["mediaType"]}" is not a valid MIME type.'}
    
@app.get('/doc/{path}') # path[r]
async def get_doc_at_path(path: str, request: Request, response: Response): # Get full document content at path
    global LINK_CACHE, LOCK
    if path in LINK_CACHE['aliases'].keys():
        _link = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]
        file_path = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]['filePath']
    elif path in LINK_CACHE['links'].keys():
        _link = LINK_CACHE['links'][path]
        file_path = LINK_CACHE['links'][path]['filePath']
    else:
        response.status_code = HTTP_404_NOT_FOUND
        return {'result': f'Document at path {path} not found in aliases or link names.'}
    if _link['mediaType']['datatype'] == 'json':
        with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'r') as f:
            content = json.load(f)
    else:
        with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'rb') as f:
            content = f'data:{_link["mediaType"]["mime"]};base64,{base64.urlsafe_b64encode(f.read()).decode("utf-8")}'
    return {'result': 'success', 'content': content, 'type': _link["mediaType"]["mime"].split('/')}

@app.post('/doc/{path}/key/{key}') # path[r], key[r], data[r]
async def post_key_to_doc(path: str, key: str, request: Request, response: Response): # Edit key (path.to.key) in doc at path
    global LINK_CACHE, LOCK
    data: dict = request.state.data

    if not 'data' in data.keys(): # Verify args
        response.status_code = HTTP_400_BAD_REQUEST
        return {'result': 'Must include "data" key in request data.'}

    # Get file path
    if path in LINK_CACHE['aliases'].keys():
        _link = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]
        file_path = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]['filePath']
    elif path in LINK_CACHE['links'].keys():
        _link = LINK_CACHE['links'][path]
        file_path = LINK_CACHE['links'][path]['filePath']
    else:
        response.status_code = HTTP_404_NOT_FOUND
        return {'result': f'Document at path {path} not found in aliases or link names.'}
    
    check_lock(_link['ids']['long'])
    LOCK.append(_link['ids']['long'])
    
    try:
        # Verify that the document is a JSON document
        if _link['mediaType']['datatype'] == 'json':
            with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'r') as f:
                content = json.load(f)
        else:
            response.status_code = HTTP_405_METHOD_NOT_ALLOWED
            return {'result': 'Cannot modify keys of a non-JSON document.'}
        
        # Check each key
        parts = key.split('.')
        execp = 'content'
        for p in parts:
            if type(eval(execp, globals(), locals())) == list:
                try:
                    int(p)
                except:
                    response.status_code = HTTP_405_METHOD_NOT_ALLOWED
                    return {'result': f'Cannot get key {p} in {execp} as {execp} is a list.'}
                if len(eval(execp, globals(), locals())) > int(p) and int(p) >= 0:
                    execp += f'[{p}]'
                else:
                    response.status_code = HTTP_404_NOT_FOUND
                    return {'result': f'Index {p} in {execp} does not exist.'}
            elif type(eval(execp, globals(), locals())) == dict:
                if p in eval(execp, globals(), locals()).keys():
                    execp += f'["{p}"]'
                else:
                    response.status_code = HTTP_404_NOT_FOUND
                    return {'result': f'Key {p} in {execp} does not exist.'}
            else:
                response.status_code = HTTP_405_METHOD_NOT_ALLOWED
                return {'result': f'Cannot edit a key in an entry that is not a dict or a list.'}
        
        # Edit document
        exec(f'{execp} = data["data"]', globals(), locals())
        with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'w') as f:
            json.dump(content, f)
    except:
        LOCK.remove(_link['ids']['long'])
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        return {'result': f'Unexpected error occurred: {traceback.format_exc()}'}
    LOCK.remove(_link['ids']['long'])
    return {'result': 'success'}

@app.get('/doc/{path}/key/{key}') # path[r], key[r]
async def get_key_in_doc(path: str, key: str, request: Request, response: Response): # Get key (path.to.key) in doc at path
    global LINK_CACHE, LOCK

    # Get file path
    if path in LINK_CACHE['aliases'].keys():
        _link = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]
        file_path = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]['filePath']
    elif path in LINK_CACHE['links'].keys():
        _link = LINK_CACHE['links'][path]
        file_path = LINK_CACHE['links'][path]['filePath']
    else:
        response.status_code = HTTP_404_NOT_FOUND
        return {'result': f'Document at path {path} not found in aliases or link names.'}
    
    # Verify that the document is a JSON document
    if _link['mediaType']['datatype'] == 'json':
        with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'r') as f:
            content = json.load(f)
    else:
        response.status_code = HTTP_405_METHOD_NOT_ALLOWED
        return {'result': 'Cannot modify keys of a non-JSON document.'}
    
    # Check each key
    parts = key.split('.')
    execp = 'content'
    for p in parts:
        if type(eval(execp, globals(), locals())) == list:
            try:
                int(p)
            except:
                response.status_code = HTTP_405_METHOD_NOT_ALLOWED
                return {'result': f'Cannot get key {p} in {execp} as {execp} is a list.'}
            if len(eval(execp, globals(), locals())) > int(p) and int(p) >= 0:
                execp += f'[{p}]'
            else:
                response.status_code = HTTP_404_NOT_FOUND
                return {'result': f'Index {p} in {execp} does not exist.'}
        elif type(eval(execp, globals(), locals())) == dict:
            if p in eval(execp, globals(), locals()).keys():
                execp += f'["{p}"]'
            else:
                response.status_code = HTTP_404_NOT_FOUND
                return {'result': f'Key {p} in {execp} does not exist.'}
        else:
            response.status_code = HTTP_405_METHOD_NOT_ALLOWED
            return {'result': f'Cannot get a key in an entry that is not a dict or a list.'}
    
    # Get data at key
    return {'result': 'success', 'data': eval(f'{execp}')}

@app.post('/doc/{path}/delete') # path[r]
async def delete_doc(path: str, request: Request, response: Response):
    global LINK_CACHE, LOCK
    if path in LINK_CACHE['aliases'].keys():
        _link = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]
        file_path = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]['filePath']
    elif path in LINK_CACHE['links'].keys():
        _link = LINK_CACHE['links'][path]
        file_path = LINK_CACHE['links'][path]['filePath']
    else:
        response.status_code = HTTP_404_NOT_FOUND
        return {'result': f'Document at path {path} not found in aliases or link names.'}
    LID = _link['ids']['long']
    check_lock(LID)
    LOCK.append(LID)
    try:
        os.remove(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path))
        for a in _link['aliases']:
            try:
                del LINK_CACHE['aliases'][a]
            except:
                pass
        del LINK_CACHE['links'][LID]
    except:
        LOCK.remove(LID)
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        return {'result': f'Unexpected error occurred: {traceback.format_exc()}'}
    LOCK.remove(LID)
    return {'result': 'success'}

@app.post('/doc/{path}/key/{key}/delete') # path[r], key[r]
async def post_delete_key_in_doc(path: str, key: str, request: Request, response: Response): # Delete key (path.to.key) in doc at path
    global LINK_CACHE, LOCK

    # Get file path
    if path in LINK_CACHE['aliases'].keys():
        _link = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]
        file_path = LINK_CACHE['links'][LINK_CACHE['aliases'][path]]['filePath']
    elif path in LINK_CACHE['links'].keys():
        _link = LINK_CACHE['links'][path]
        file_path = LINK_CACHE['links'][path]['filePath']
    else:
        response.status_code = HTTP_404_NOT_FOUND
        return {'result': f'Document at path {path} not found in aliases or link names.'}
    
    check_lock(_link['ids']['long'])
    LOCK.append(_link['ids']['long'])
    
    try:
        # Verify that the document is a JSON document
        if _link['mediaType']['datatype'] == 'json':
            with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'r') as f:
                content = json.load(f)
        else:
            response.status_code = HTTP_405_METHOD_NOT_ALLOWED
            return {'result': 'Cannot modify keys of a non-JSON document.'}
        
        # Check each key
        parts = key.split('.')
        execp = 'content'
        for p in parts:
            if type(eval(execp, globals(), locals())) == list:
                try:
                    int(p)
                except:
                    response.status_code = HTTP_405_METHOD_NOT_ALLOWED
                    return {'result': f'Cannot get key {p} in {execp} as {execp} is a list.'}
                if len(eval(execp, globals(), locals())) > int(p) and int(p) >= 0:
                    execp += f'[{p}]'
                else:
                    response.status_code = HTTP_404_NOT_FOUND
                    return {'result': f'Index {p} in {execp} does not exist.'}
            elif type(eval(execp, globals(), locals())) == dict:
                if p in eval(execp, globals(), locals()).keys():
                    execp += f'["{p}"]'
                else:
                    response.status_code = HTTP_404_NOT_FOUND
                    return {'result': f'Key {p} in {execp} does not exist.'}
            else:
                response.status_code = HTTP_405_METHOD_NOT_ALLOWED
                return {'result': f'Cannot delete a key in an entry that is not a dict or a list.'}
        
        # delete
        exec(f'del {execp}', globals(), locals())
        with open(os.path.join(*default(CONFIG, 'databaseRoot', 'root').split('/'), file_path), 'w') as f:
            json.dump(content, f)
    except:
        LOCK.remove(_link['ids']['long'])
        response.status_code = HTTP_500_INTERNAL_SERVER_ERROR
        return {'result': f'Unexpected error occurred: {traceback.format_exc()}'}
    LOCK.remove(_link['ids']['long'])
    return {'result': 'success'}

if __name__ == '__main__':
    uvicorn.run('server:app', host=default(CONFIG, 'host', 'localhost'), port=default(CONFIG, 'port', 88), access_log=default(CONFIG, 'logRequests', False))