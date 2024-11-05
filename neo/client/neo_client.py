import json
import os
from datetime import datetime
import re
from dotenv import load_dotenv

import requests
from flask import request
from models import ApiKeyCredential, PwdCredential, User
load_dotenv()

class NEO():
    def __init__(self, uri, credential):
        self.session = requests.session()
        self.uri = uri
        self.system_credentials = ApiKeyCredential(os.getenv('NEO_KEY'), os.getenv('NEO_SECRET'))
        self.child_table_method = os.getenv('NEO_CHILD_API')
        if isinstance(credential, PwdCredential):
            self.usr = credential.user
            self.pwd = credential.password
            self.authenticate()
        elif isinstance(credential, ApiKeyCredential):
            self.api_key = credential.api_key
            self.api_secret = credential.api_secret
            self.authenticate(use_key=True)
        else:
            raise Exception('Credential Type invalid. Use ApiKeyCredential or PwdCredential')

    def authenticate(self, use_key=False):
        response = None
        try:
            session = requests.Session()
            if use_key:
                session.headers.update({
                    'Authorization': f'token {self.api_key}:{self.api_secret}'
                })
                response = session.get(f'{self.uri}/api/method/get_auth_user')
                response.raise_for_status()
                data = response.json()
                self.session = session
                if 'data' in data and 'user' in data['data'] and data['data']['user'] != 'Gest':
                    self.session = session
                    self.usr = data['data']['user'] 
                    return self.session
                else:
                    self.session = None
                    raise Exception(f'Invalid Credentials.')
            else:
                response = session.post(f'{self.uri}/api/method/login', {'usr': self.usr, 'pwd': self.pwd})
                response.raise_for_status()

                data = response.json()
                if "message" in data and data["message"] == "Logged In":
                    self.session = session
                    return self.session
                else:
                    self.session = None
                    raise Exception(f'Invalid Credentials.')

        except requests.exceptions.RequestException as e:
            self.log_error(response, f'Authentication error. {str(e)}')
            raise Exception(f'Authentication error. {str(e)}')

    def register(self, email, password, first_name, last_name):
        if not self.verify_password_strength(password):
            return {'message': 'Password is not stronger.'}, 400
        user = User(True)
        user.email = email
        user.username = email
        user.first_name = first_name
        user.new_password = password
        user.last_name = last_name

        try:
            response = self.create(doctype='User', data=user.__dict__)
            return {'message': 'Please check your email to proceed with registration.', 'key': response["reset_password_key"]}
        except Exception as ex:
            raise(ex)

    def get_one(self, doctype, name):
        response = None
        try:
            response = self.session.get(f'{self.uri}/api/resource/{doctype}/{name}')
            response.raise_for_status()
            data = response.json()
            return data['data']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f"Request error: {e}")

    def get_all_(self, doctype, filters=None, fields=None, dump_params=True, all=False):
        session = self.session
        response = None
        try:
            if not all:
                filter_str = ''
                fields_str = ''

                if filters:
                    filter_str = json.dumps(filters) if dump_params else filters
                if fields:
                    fields_str = json.dumps(fields) if dump_params else fields

                url = f'{self.uri}/api/resource/{doctype}'

                if filters:
                    url += f'?filters={filter_str}'
                if fields:
                    url += f'&fields={fields_str}' if filters else f'?fields={fields_str}'

                response = session.get(url)
                response.raise_for_status()

                data = response.json()
                return data['data']
            else:
                response = session.get(f'{self.uri}/api/resource/{doctype}?fields=["*"]')
                response.raise_for_status()

                data = response.json()
                return data['data']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def get_all(self, doctype, filters=[], fields=['*'], dump_params=True, all=False):
        """Deprecated!"""
        session = self.session
        response = None
        try:
            if not all:
                filter_str = json.dumps(filters) if dump_params else filters 
                fields_str = json.dumps(fields) if dump_params else fields

                response = session.get(f'{self.uri}/api/resource/{doctype}?filters={filter_str}&fields={fields_str}') if filters and fields else session.get(f'{self.uri}/api/resource/{doctype}')
                response.raise_for_status()

                data = response.json()
                return data['data']
            else:
                response = session.get(f'{self.uri}/api/resource/{doctype}?fields=["*"]')
                response.raise_for_status()

                data = response.json()
                return data['data']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def create(self, doctype, data, dump_data=True):
        response = None
        try:
            session = self.session
            response = session.post(f'{self.uri}/api/resource/{doctype}', json.dumps(data)) if dump_data else session.post(f'{self.uri}/api/resource/{doctype}', data)
            response.raise_for_status()

            data = response.json()
            return data['data']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def create_child_table(self, data, dump_data=True):
        response = None
        try:
            session = self.session
            response = session.post(f'{self.child_table_method}', json.dumps(data)) if dump_data else session.post(f'{self.child_table_method}', data)
            response.raise_for_status()

            data = response.json()
            return data['message']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def update(self, doctype, name, data: dict):
        response = None
        try:
            session = self.session
            response = session.put(f'{self.uri}/api/resource/{doctype}/{name}', json.dumps(data))
            response.raise_for_status()  # Lança uma exceção se houver um erro HTTP

            data = response.json()
            return data['data']

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {e}')

    def delete(self, doctype, name):
        response = None
        try:
            session = self.session
            response = session.delete(f'{self.uri}/api/resource/{doctype}/{name}')
            response.raise_for_status()

            data = response.json()
            return data
        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def call_method(self, method_name, http_method='GET', data=None):
        methods = ['GET', 'POST']
        response = None
        if http_method not in methods:
            raise Exception(f'HTTP Method not allowed. Use {methods} instead.')
        try:
            session = self.session
            if http_method == 'GET':
                response = session.get(f'{self.uri}/api/method/{method_name}')
            else:
                response = session.post(f'{self.uri}/api/method/{method_name}', json.dumps(data))

            response.raise_for_status()

            data = response.json()
            return data

        except requests.exceptions.RequestException as e:
            self.log_error(response, f"Request error: {e}")
            raise Exception(f'Request error. {str(e)}')

    def verify_password_strength(self, pwd):
        """
        Verifica se uma senha é forte, atendendo aos seguintes critérios:
        - Mínimo de 8 caracteres
        - Pelo menos uma letra maiúscula
        - Pelo menos uma letra minúscula
        - Pelo menos um número
        - Pelo menos um caractere especial
     (!@#$%^&*()_-+={}[]|;:'",.<>\/?)
        """

        # Expressões regulares para cada critério
        criterias = [
            r'.{8,}',  # Mínimo de 8 caracteres
            r'[A-Z]',  # Pelo menos uma letra maiúscula
            r'[a-z]',  # Pelo menos uma letra minúscula
            r'\d',     # Pelo menos um número
            r'[!@#$%^&*()_\-+={}[]|;:\'",.<>\/?]'  # Pelo menos um caractere especial
        ]

        # Verifica se a senha atende a todos os critérios
        for criteria in criterias:
            if not re.search(criteria, pwd):
                return False  

        return True
