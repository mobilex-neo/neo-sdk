class ApiKeyCredential():
    def __init__(self, api_key, api_secret, token_type='token'):
        self.api_key = api_key
        self.api_secret = api_secret
        self.token_type = token_type
        