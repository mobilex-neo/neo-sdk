# NEO SDK for Python

[![PyPI version](https://badge.fury.io/py/neo-sdk-py.svg)](https://badge.fury.io/py/neo-sdk)

The NEO SDK for Python is a powerful tool that allows developers to seamlessly interact with the NEO platform. With this SDK, you can easily perform various operations, including:

- **Authentication:** Securely authenticate with the NEO platform using API keys or username/password combinations.
- **Data Management:** Effortlessly retrieve, create, update, and delete data within your NEO instance.
- **Method Execution:** Execute custom methods defined in your NEO applications.
- **Password Strength Verification:** Ensure the robustness of user passwords with built-in password strength checks.

## Installation

You can install the NEO SDK for Python using pip:

```bash
pip install neo-sdk

````

or

```bash
pip install -e git+https://github.com/mobilex-neo/neo-sdk.git#egg=neo-sdk

```

# Getting Started
To start using the NEO SDK, you'll need to import the necessary classes and initialize the NEO client:

```python
import os
from dotenv import load_dotenv
from neo.client.neo_client import NEO
from neo.models import ApiKeyCredential, PwdCredential

# Load environment variables from .env file
load_dotenv()

# Replace with your actual NEO instance URI
uri = os.getenv('NEO_URI')

# Authentication using API key
api_key = os.getenv('NEO_KEY')
api_secret = os.getenv('NEO_SECRET')
api_credential = ApiKeyCredential(api_key, api_secret)
neo_api = NEO(uri, api_credential)

# Authentication using username and password
username = os.getenv('NEO_TEST_USER')
password = os.getenv('NEO_TEST_PASSWORD')
pwd_credential = PwdCredential(username, password)
neo_api = NEO(uri, pwd_credential)

```

# Usage
## Getting a Single Document

```python
doctype = 'ToDo'
docname = 'test_todo'
data = neo_api.get_one(doctype, docname)
print(data)

```

## Getting All Documents of a Doctype

```python
doctype = 'ToDo'
data = neo_api.get_all(doctype)
print(data)
````
## Creating a New Document

```python
doctype = 'ToDo'
data = {'key': 'value'}
new_doc = neo_api.create(doctype, data)
print(new_doc)

```

## Updating an Existing Document

```python
doctype = 'ToDo'
docname = 'test_todo'
data = {'key': 'new_value'}
updated_doc = neo_api.update(doctype, docname, data)
print(updated_doc)
````

## Deleting a Document

```python
doctype = 'ToDo'
docname = 'test_todo'
deleted_doc = neo_api.delete(doctype, docname)
print(deleted_doc)
```

## Calling a Custom Method

```python
method_name = 'test_method'
http_method = 'GET'  # or 'POST'
data = {'key': 'value'}  # Optional data for POST requests
response = neo_api.call_method(method_name, http_method, data)
print(response)
````

## Verifying Password Strength

```python
password = 'Teste@123'
is_strong = neo_api.verify_password_strength(password)
print(is_strong)
````

# Contributing
Contributions to the NEO SDK for Python are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request on the GitHub repository.

# License
This project is licensed under the MIT License - see the LICENSE.md file for details.

