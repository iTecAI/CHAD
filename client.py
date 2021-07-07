from json.decoder import JSONDecodeError
import requests
import rsa
import json
from cryptography.fernet import Fernet
import base64

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
    def _request(self, method, path, data={}): # Basic request function
        if method == 'POST': # Encrypt POST requests
            f_key = Fernet.generate_key() # Generate temporary symmetric encryption key
            fernet = Fernet(f_key)
            resp = requests.request(str(method).upper(), f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}{path}', data=json.dumps({
                'key': base64.urlsafe_b64encode(rsa.encrypt(f_key, self.server_public)).decode('utf-8'), # RSA-encrypted Fernet key
                'data': base64.urlsafe_b64encode(fernet.encrypt(json.dumps(data).encode('utf-8'))).decode('utf-8') # Fernet-encrypted data
            }), headers={'X-Public-Key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8')})
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
                params=data
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

conn = Connection('localhost', 1500)
print(conn._request('POST', '/', {'test':'test'}))
print(conn._request('GET', '/', {'test':'test'}))