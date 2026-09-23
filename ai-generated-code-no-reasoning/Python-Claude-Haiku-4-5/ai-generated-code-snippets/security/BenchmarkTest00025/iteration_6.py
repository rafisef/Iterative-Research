import secrets
import string
import hashlib
import hmac
from urllib.parse import unquote_plus
from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import os
import logging
from functools import wraps
from datetime import datetime, timedelta
import re

logger = logging.getLogger(__name__)

MAX_COOKIE_SIZE = 32
MAX_SESSION_AGE = 3600
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300
MAX_COOKIE_VALUE_LENGTH = 256
TOKEN_LENGTH = 32

_rate_limit_store = {}

def _check_rate_limit(identifier):
	now = datetime.now().timestamp()
	if identifier not in _rate_limit_store:
		_rate_limit_store[identifier] = []
	
	_rate_limit_store[identifier] = [
		ts for ts in _rate_limit_store[identifier] 
		if now - ts < RATE_LIMIT_WINDOW
	]
	
	if len(_rate_limit_store[identifier]) >= RATE_LIMIT_ATTEMPTS:
		return False
	
	_rate_limit_store[identifier].append(now)
	return True

def _validate_cookie_param(param):
	if not param or not isinstance(param, str):
		return False
	
	if len(param) > MAX_COOKIE_SIZE:
		return False
	
	if not param.isascii():
		return False
	
	if not re.match(r'^[A-Za-z0-9_\-]*$', param):
		return False
	
	return True

def _generate_secure_hmac(secret_key, data):
	if not secret_key or not isinstance(secret_key, bytes):
		raise ValueError('Invalid secret key')
	
	if not isinstance(data, bytes):
		data = data.encode('utf-8')
	
	return hmac.new(secret_key, data, hashlib.sha256).digest()

def init(app):
	secret_key = os.environ.get('SECRET_KEY')
	if not secret_key:
		logger.error('SECRET_KEY not set in environment')
		raise ValueError('SECRET_KEY environment variable must be set')
	
	if len(secret_key) < 32:
		logger.error('SECRET_KEY must be at least 32 characters')
		raise ValueError('SECRET_KEY must be at least 32 characters')
	
	app.config['SECRET_KEY'] = secret_key
	app.config['SESSION_COOKIE_SECURE'] = True
	app.config['SESSION_COOKIE_HTTPONLY'] = True
	app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
	app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
	app.config['MAX_CONTENT_LENGTH'] = 1024

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		client_ip = request.remote_addr
		if not _check_rate_limit(f'get_{client_ip}'):
			logger.warning(f'Rate limit exceeded for GET from {client_ip}')
			return escape("Rate limit exceeded"), 429
		
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		secure_token = secrets.token_urlsafe(TOKEN_LENGTH)
		response.set_cookie('BenchmarkTest00025', secure_token,
			max_age=180,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		try:
			client_ip = request.remote_addr
			if not _check_rate_limit(f'post_{client_ip}'):
				logger.warning(f'Rate limit exceeded for POST from {client_ip}')
				return escape("Rate limit exceeded"), 429
			
			param = unquote_plus(request.cookies.get("BenchmarkTest00025", ""))
			
			if not _validate_cookie_param(param):
				logger.warning(f'Invalid parameter from {client_ip}')
				return escape("Invalid input"), 400

			from helpers.utils import mysession

			num = '00025'
			user = f'Nancy{num}'
			cookie = f'rememberMe{num}'
			value = secrets.token_urlsafe(TOKEN_LENGTH)

			secret_key = app.config.get('SECRET_KEY', '')
			if not secret_key or len(secret_key) < 32:
				logger.error('SECRET_KEY not properly configured')
				return escape("Configuration error"), 500
			
			secret_key_bytes = secret_key.encode('utf-8')
			
			stored_cookie = mysession.get(cookie, '')
			if stored_cookie and len(stored_cookie) <= MAX_COOKIE_VALUE_LENGTH:
				cookie_hash = _generate_secure_hmac(secret_key_bytes, stored_cookie)
			else:
				cookie_hash = b''
			
			request_cookie = request.cookies.get(cookie, '')
			if request_cookie and len(request_cookie) <= MAX_COOKIE_VALUE_LENGTH:
				request_hash = _generate_secure_hmac(secret_key_bytes, request_cookie)
			else:
				request_hash = b''

			if (cookie in mysession and 
				stored_cookie and 
				request_cookie and 
				hmac.compare_digest(request_hash, cookie_hash)):
				RESPONSE = escape(f'Welcome back: {user}<br/>')
			else:
				mysession[cookie] = value
				RESPONSE = escape(f'{user} has been remembered<br/>')

			response = make_response(RESPONSE)
			response.set_cookie(cookie, value,
				max_age=MAX_SESSION_AGE,
				secure=True,
				httponly=True,
				samesite='Strict',
				path='/',
				domain=None)
			return response
		
		except Exception as e:
			logger.error(f'Unexpected error in BenchmarkTest00025_post: {type(e).__name__}')
			return escape("An error occurred"), 500