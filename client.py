from json.decoder import JSONDecodeError
import requests
import rsa
import json
from cryptography.fernet import Fernet
import base64
import subprocess
import random
import sys
import time

class CHADException(Exception):
    pass
class Connection:
    def __init__(self, host, port, protocol='http'):
        self.addr = (host, port)
        self.protocol = protocol
        self.public, self.private = rsa.newkeys(512)
        self.server_public = rsa.PublicKey.load_pkcs1( # Get public key from server
            base64.urlsafe_b64decode(
                requests.get(f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}')
                    .headers['X-Public-Key']
            )
        )
    def _request(self, method, path, params={}, data={}): # Basic request function
        if method == 'POST': # Encrypt POST requests
            f_key = Fernet.generate_key() # Generate temporary symmetric encryption key
            fernet = Fernet(f_key)
            resp = requests.request(
                str(method).upper(), f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}{path}', 
                data=json.dumps({
                    'key': base64.urlsafe_b64encode(rsa.encrypt(f_key, self.server_public)).decode('utf-8'), # RSA-encrypted Fernet key
                    'data': base64.urlsafe_b64encode(fernet.encrypt(json.dumps(data).encode('utf-8'))).decode('utf-8') # Fernet-encrypted data
                }), 
                headers={'X-Public-Key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8')},
                params=params
            )
            self.server_public = rsa.PublicKey.load_pkcs1( # Update server public key
                base64.urlsafe_b64decode(
                    resp.headers['X-Public-Key']
                )
            )
            # Decrypt recieved response
            try:
                raw_json = resp.json()
            except JSONDecodeError:
                raise ConnectionError(f'Recieved a non-JSON response from the CHAD server: "{str(resp.text)}" with status code {str(resp.status_code)}.')
            encrypted_data = base64.urlsafe_b64decode(raw_json['data'].encode('utf-8'))
            encryption_key = Fernet(rsa.decrypt(base64.urlsafe_b64decode(raw_json['key'].encode('utf-8')), self.private)) # get Fernet key
            decrypted_data = encryption_key.decrypt(encrypted_data).decode('utf-8') # Decrypt data
            # Return as JSON if possible, otherwise return raw data as string
            try:
                return json.loads(decrypted_data)
            except JSONDecodeError:
                return decrypted_data
        else: # Do not encrypt GET requests, but decrypt response body
            resp = requests.request(
                str(method).upper(), f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}{path}', 
                headers={'x-public-key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8')},
                params=params
            )
            # Decrypt recieved response
            try:
                raw_json = resp.json()
            except JSONDecodeError:
                raise ConnectionError(f'Recieved a non-JSON response from the CHAD server: "{str(resp.text)}" with status code {str(resp.status_code)}.')
            encrypted_data = base64.urlsafe_b64decode(raw_json['data'].encode('utf-8'))
            encryption_key = Fernet(rsa.decrypt(base64.urlsafe_b64decode(raw_json['key'].encode('utf-8')), self.private)) # get Fernet key
            decrypted_data = encryption_key.decrypt(encrypted_data).decode('utf-8') # Decrypt data
            # Return as JSON if possible, otherwise return raw data as string
            try:
                return json.loads(decrypted_data)
            except JSONDecodeError:
                return decrypted_data
    
    def create_document(self, content, path='', mimetype='application/json', longId=None, shortId=None): # Create a new document
        # Assemble request from args
        data = {
            'content': content,
            'mediaType': mimetype,
            'documentPath': path
        }
        if longId:
            data['longId'] = longId
        if shortId:
            data['shortId'] = shortId
        
        # Process request & response
        response_data = self._request('POST', '/doc/new', data=data)
        if response_data['result'] == 'success':
            return {
                'ids': {
                    'long': response_data['longId'],
                    'short': response_data['shortId']
                },
                'aliases': response_data['aliases']
            }
        else:
            raise CHADException(f'Failed to create a new document: {response_data["result"]}')
    
    def get_document(self, path): # Get whole document at path
        response_data = self._request('GET', f'/doc/{path}')
        if not response_data['result'] == 'success':
            raise CHADException(f'Failed to get document at path {path}: {response_data["result"]}')
        if response_data['type'][1] == 'json':
            return response_data['content']
        else:
            return base64.urlsafe_b64decode(response_data['content'].split('base64,')[1].encode('utf-8'))
    
    def edit_document_key(self, document_path, key, data): # Edit portion of document at key
        resp = self._request('POST', f'/doc/{str(document_path)}/key/{str(key)}', data={'data': data})
        if resp['result'] == 'success':
            return 
        else:
            raise CHADException(f'Failed to edit key {key} in document {document_path}: {resp["result"]}')
    
    def get_document_key(self, document_path, key): # Get portion of document at key
        resp = self._request('GET', f'/doc/{str(document_path)}/key/{str(key)}')
        if resp['result'] == 'success':
            return resp['data']
        else:
            raise CHADException(f'Failed to edit key {key} in document {document_path}: {resp["result"]}')
    
    def delete_document(self, path): # Delete whole document at path
        response_data = self._request('POST', f'/doc/{path}/delete')
        if not response_data['result'] == 'success':
            raise CHADException(f'Failed to delete document at path {path}: {response_data["result"]}')
    
    def delete_document_key(self, document_path, key): # Delete portion of document at key
        resp = self._request('POST', f'/doc/{str(document_path)}/key/{str(key)}/delete')
        if resp['result'] == 'success':
            return
        else:
            raise CHADException(f'Failed to delete key {key} in document {document_path}: {resp["result"]}')

class SelfContainedConnection(Connection):
    def __init__(
        self, 
        root='chad_db', 
        port=random.randint(8000, 32000), 
        protocol='http', 
        server_python='server.py', 
        alias_length=12, 
        log_access=False, 
        log_destination=sys.stdout
    ):
        self.serverProcess = subprocess.Popen([sys.executable, server_python, '--config', json.dumps({
            'host': 'localhost',
            'port': port,
            'databaseRoot': root,
            'aliasLength': alias_length,
            'logRequests': log_access
        })], stdout=log_destination)
        time.sleep(1)
        super().__init__('localhost', port, protocol=protocol)
    
    def close(self):
        self.serverProcess.kill()

db = SelfContainedConnection()
db.create_document({'test': {'test2': 'electric boogaloo'}})
time.sleep(2)
db.close()