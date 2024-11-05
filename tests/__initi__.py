import unittest
from unittest.mock import patch, Mock
import requests
import os
from dotenv import load_dotenv
from neo.client.neo_client import NEO
from neo.models import ApiKeyCredential, PwdCredential, User

load_dotenv()

class TestNEO(unittest.TestCase):

	def setUp(self):
		self.uri = os.getenv('NEO_URI')
		self.api_key = os.getenv('NEO_KEY')
		self.api_secret = os.getenv('NEO_SECRET')
		self.test_user = os.getenv('NEO_TEST_USER')
		self.test_password = os.getenv('NEO_TEST_PASSWORD')
		self.api_credential = ApiKeyCredential(self.api_key, self.api_secret)
		self.pwd_credential = PwdCredential(self.test_user, self.test_password)
		self.neo_api = NEO(self.uri, self.api_credential)
		self.doctype = 'ToDo'
		self.docname = 'test_todo'

	def test_init_with_ApiKeyCredential(self):
		neo = NEO(self.uri, self.api_credential)
		self.assertEqual(neo.uri, self.uri)
		self.assertIsInstance(neo.session, requests.Session)

	def test_init_with_PwdCredential(self):
		neo = NEO(self.uri, self.pwd_credential)
		self.assertEqual(neo.uri, self.uri)
		self.assertIsInstance(neo.session, requests.Session)

	@patch('neo.client.neo_client.requests.Session')
	def test_authenticate_with_ApiKeyCredential_success(self, mock_session):
		mock_response = Mock()
		mock_response.json.return_value = {'data': {'user': 'testuser'}}
		mock_session().get.return_value = mock_response
		neo = NEO(self.uri, self.api_credential)
		self.assertIsInstance(neo.session, requests.Session)

	@patch('neo.client.neo_client.requests.Session')
	def test_authenticate_with_ApiKeyCredential_failure(self, mock_session):
		mock_response = Mock()
		mock_response.json.return_value = {'data': {'user': 'Gest'}}
		mock_session().get.return_value = mock_response
		with self.assertRaises(Exception):
			NEO(self.uri, self.api_credential)

	@patch('neo.client.neo_client.requests.Session')
	def test_authenticate_with_PwdCredential_success(self, mock_session):
		mock_response = Mock()
		mock_response.json.return_value = {"message": "Logged In"}
		mock_session().post.return_value = mock_response
		neo = NEO(self.uri, self.pwd_credential)
		self.assertIsInstance(neo.session, requests.Session)

	@patch('neo.client.neo_client.requests.Session')
	def test_authenticate_with_PwdCredential_failure(self, mock_session):
		mock_response = Mock()
		mock_response.json.return_value = {"message": "Login Failed"}
		mock_session().post.return_value = mock_response
		with self.assertRaises(Exception):
			NEO(self.uri, self.pwd_credential)

	@patch('neo.client.neo_client.requests.Session.get')
	def test_get_one_success(self, mock_get):
		mock_response = Mock()
		mock_response.json.return_value = {'data': {'key': 'value'}}
		mock_get.return_value = mock_response
		data = self.neo_api.get_one(self.doctype, self.docname)
		self.assertEqual(data, {'key': 'value'})

	@patch('neo.client.neo_client.requests.Session.get')
	def test_get_one_failure(self, mock_get):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_get.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.get_one(self.doctype, self.docname)

	@patch('neo.client.neo_client.requests.Session.get')
	def test_get_all_success(self, mock_get):
		mock_response = Mock()
		mock_response.json.return_value = {'data': [{'key': 'value1'}, {'key': 'value2'}]}
		mock_get.return_value = mock_response
		data = self.neo_api.get_all(self.doctype)
		self.assertEqual(data, [{'key': 'value1'}, {'key': 'value2'}])

	@patch('neo.client.neo_client.requests.Session.get')
	def test_get_all_failure(self, mock_get):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_get.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.get_all(self.doctype)

	@patch('neo.client.neo_client.requests.Session.post')
	def test_create_success(self, mock_post):
		mock_response = Mock()
		mock_response.json.return_value = {'data': {'name': 'test_doc'}}
		mock_post.return_value = mock_response
		data = self.neo_api.create(self.doctype, {'key': 'value'})
		self.assertEqual(data, {'name': 'test_doc'})

	@patch('neo.client.neo_client.requests.Session.post')
	def test_create_failure(self, mock_post):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_post.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.create(self.doctype, {'key': 'value'})

	@patch('neo.client.neo_client.requests.Session.put')
	def test_update_success(self, mock_put):
		mock_response = Mock()
		mock_response.json.return_value = {'data': {'key': 'new_value'}}
		mock_put.return_value = mock_response
		data = self.neo_api.update(self.doctype, self.docname, {'key': 'new_value'})
		self.assertEqual(data, {'key': 'new_value'})

	@patch('neo.client.neo_client.requests.Session.put')
	def test_update_failure(self, mock_put):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_put.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.update(self.doctype, self.docname, {'key': 'new_value'})

	@patch('neo.client.neo_client.requests.Session.delete')
	def test_delete_success(self, mock_delete):
		mock_response = Mock()
		mock_response.json.return_value = {'message': 'ok'}
		mock_delete.return_value = mock_response
		data = self.neo_api.delete(self.doctype, self.docname)
		self.assertEqual(data, {'message': 'ok'})

	@patch('neo.client.neo_client.requests.Session.delete')
	def test_delete_failure(self, mock_delete):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_delete.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.delete(self.doctype, self.docname)

	@patch('neo.client.neo_client.requests.Session.get')
	def test_call_method_get_success(self, mock_get):
		mock_response = Mock()
		mock_response.json.return_value = {'message': 'ok'}
		mock_get.return_value = mock_response
		data = self.neo_api.call_method('test_method', 'GET')
		self.assertEqual(data, {'message': 'ok'})

	@patch('neo.client.neo_client.requests.Session.post')
	def test_call_method_post_success(self, mock_post):
		mock_response = Mock()
		mock_response.json.return_value = {'message': 'ok'}
		mock_post.return_value = mock_response
		data = self.neo_api.call_method('test_method', 'POST', {'key': 'value'})
		self.assertEqual(data, {'message': 'ok'})

	def test_call_method_invalid_http_method(self):
		with self.assertRaises(Exception):
			self.neo_api.call_method('test_method', 'PUT')

	@patch('neo.client.neo_client.requests.Session.get')
	def test_call_method_failure(self, mock_get):
		mock_response = Mock()
		mock_response.raise_for_status.side_effect = requests.exceptions.RequestException('Test Error')
		mock_get.return_value = mock_response
		with self.assertRaises(Exception):
			self.neo_api.call_method('test_method', 'GET')

	def test_verify_password_strength(self):
		self.assertTrue(self.neo_api.verify_password_strength('Teste@123'))
		self.assertFalse(self.neo_api.verify_password_strength('teste123'))
		self.assertFalse(self.neo_api.verify_password_strength('Testeteste'))
		self.assertFalse(self.neo_api.verify_password_strength('Teste@teste'))
		self.assertFalse(self.neo_api.verify_password_strength('Test123'))

if __name__ == '__main__':
	unittest.main()
