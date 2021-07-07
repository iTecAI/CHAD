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
        self.server_public = rsa.PublicKey.load_pkcs1(
            base64.urlsafe_b64decode(
                requests.get(f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}')
                    .headers['X-Public-Key']
            )
        )
    def _request(self, method, path, data):
        f_key = Fernet.generate_key()
        fernet = Fernet(f_key)
        resp = requests.request(str(method).upper(), f'{self.protocol}://{self.addr[0]}:{str(self.addr[1])}{path}', data=json.dumps({
            'key': base64.urlsafe_b64encode(rsa.encrypt(f_key, self.server_public)).decode('utf-8'),
            'data': base64.urlsafe_b64encode(fernet.encrypt(json.dumps(data).encode('utf-8'))).decode('utf-8')
        }), headers={'X-Public-Key': base64.urlsafe_b64encode(self.public.save_pkcs1()).decode('utf-8')})
        self.server_public = rsa.PublicKey.load_pkcs1(
            base64.urlsafe_b64decode(
                resp.headers['X-Public-Key']
            )
        )
        try:
            raw_json = resp.json()
        except JSONDecodeError:
            raise ConnectionError(f'Recieved a non-JSON response from the CHAD server: "{str(resp.text)}" with status code {str(resp.status_code)}.')
        encrypted_data = base64.urlsafe_b64decode(raw_json['data'].encode('utf-8'))
        encryption_key = Fernet(rsa.decrypt(base64.urlsafe_b64decode(raw_json['key'].encode('utf-8')), self.private))
        decrypted_data = encryption_key.decrypt(encrypted_data).decode('utf-8')
        try:
            return json.loads(decrypted_data)
        except JSONDecodeError:
            return decrypted_data