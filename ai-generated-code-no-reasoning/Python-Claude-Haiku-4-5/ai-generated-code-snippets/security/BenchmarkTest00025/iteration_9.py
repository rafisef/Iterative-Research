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
from collections import defaultdict
import threading

logger = logging.getLogger(__name__)

MAX_COOKIE_SIZE = 32
MAX_SESSION_AGE = 3600
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300
MAX_COOKIE_VALUE_LENGTH = 256
TOKEN_LENGTH = 32
CLEANUP_INTERVAL = 3600
MAX_IP_LENGTH = 45
MAX_IDENTIFIER_LENGTH = 256

_rate_limit_store = defaultdict(list)
_last_cleanup = datetime.now()
_rate_limit_lock = threading.Lock()

def _cleanup_rate_limit_store():
	global _last_cleanup
	with _rate_limit_lock:
		now = datetime.now()
		if (now - _last_cleanup).total_seconds() > CLEANUP_INTERVAL:
			for identifier in list(_rate_limit_store.keys()):
				if not _rate_limit_store[identifier]:
					del _rate_limit_store[identifier]
			_last_cleanup = now

def _check_rate_limit(identifier):
	_cleanup_rate_limit_store()
	
	if not isinstance(identifier, str) or len(identifier) > MAX_IDENTIFIER_LENGTH:
		return False
	
	with _rate_limit_lock:
		now = datetime.now().timestamp()
		
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

def _is_valid_ip(ip_string):
	if not ip_string or not isinstance(ip_string, str):
		return False
	if len(ip_string) > MAX_IP_LENGTH:
		return False
	ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
	ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
	if re.match(ipv4_pattern, ip_string):
		parts = ip_string.split('.')
		if all(0 <= int(p) <= 255 for p in parts):
			return True
	if re.match(ipv6_pattern, ip_string):
		return True
	return False

def _get_client_identifier(request_obj):
	client_ip = request_obj.remote_addr
	user_agent = request_obj.headers.get('User-Agent', '')
	if not isinstance(user_agent, str):
		user_agent = ''
	user_agent = user_agent[:128]
	combined = f"{client_ip}:{user_agent}"
	return hashlib.sha256(combined.encode('utf-8')).hexdigest()

def _validate_request_method(required_method):
	def decorator(f):
		@wraps(f)
		def decorated_function(*args, **kwargs):
			if request.method != required_method:
				return escape("Method not allowed"), 405
			return f(*args, **kwargs)
		return decorated_function
	return decorator

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
	app.config['JSON_SORT_KEYS'] = False
	app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False
	app.config['SESSION_COOKIE_NAME'] = '__Secure-session'

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		client_ip = request.remote_addr
		if not _is_valid_ip(client_ip):
			logger.warning(f'Invalid IP address attempt')
			return escape("Invalid request"), 400
		
		client_id = _get_client_identifier(request)
		if not _check_rate_limit(f'get_{client_id}'):
			logger.warning(f'Rate limit exceeded for GET')
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
			if request.method != 'POST':
				return escape("Method not allowed"), 405

			client_ip = request.remote_addr
			if not _is_valid_ip(client_ip):
				logger.warning(f'Invalid IP address attempt')
				return escape("Invalid request"), 400
			
			client_id = _get_client_identifier(request)
			if not _check_rate_limit(f'post_{client_id}'):
				logger.warning(f'Rate limit exceeded for POST')
				return escape("Rate limit exceeded"), 429
			
			param = unquote_plus(request.cookies.get("BenchmarkTest00025", ""))
			
			if not _validate_cookie_param(param):
				logger.warning(f'Invalid parameter submitted')
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
			if stored_cookie and isinstance(stored_cookie, str) and len(stored_cookie) <= MAX_COOKIE_VALUE_LENGTH:
				cookie_hash = _generate_secure_hmac(secret_key_bytes, stored_cookie)
			else:
				cookie_hash = b''
			
			request_cookie = request.cookies.get(cookie, '')
			if request_cookie and isinstance(request_cookie, str) and len(request_cookie) <= MAX_COOKIE_VALUE_LENGTH:
				request_hash = _generate_secure_hmac(secret_key_bytes, request_cookie)
			else:
				request_hash = b''

			if (cookie in mysession and 
				stored_cookie and 
				request_cookie and 
				len(cookie_hash) == len(request_hash) and
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
			logger.error(f'Unexpected error in BenchmarkTest00025_post')
			return escape("An error occurred"), 500