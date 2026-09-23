from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.utils
import io
import logging
import re
import secrets
import hashlib
from functools import wraps
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import ipaddress

logger = logging.getLogger(__name__)

ALLOWED_COOKIE_PATTERN = re.compile(r'^[\x20-\x7E]{0,500}$')
VALID_COOKIE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]{1,100}$')
MAX_COOKIE_VALUE_LENGTH = 500
MAX_COOKIE_PARAM_LENGTH = 500
COOKIE_MAX_AGE = 3600
REQUEST_TIMEOUT = 30
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10

_request_log = defaultdict(list)
_request_log_lock = threading.RLock()
_cleanup_time = datetime.now()

def _validate_client_ip(client_id):
	try:
		ipaddress.ip_address(client_id)
		return client_id
	except ValueError:
		return 'unknown'

def _cleanup_request_log():
	global _cleanup_time
	now = datetime.now()
	if (now - _cleanup_time).total_seconds() > RATE_LIMIT_WINDOW:
		with _request_log_lock:
			cutoff = now - timedelta(seconds=RATE_LIMIT_WINDOW)
			for client_id in list(_request_log.keys()):
				_request_log[client_id] = [
					t for t in _request_log[client_id] 
					if t > cutoff
				]
				if not _request_log[client_id]:
					del _request_log[client_id]
		_cleanup_time = now

def rate_limit(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		_cleanup_request_log()
		
		client_id = request.remote_addr or 'unknown'
		client_id = _validate_client_ip(client_id)
		
		current_time = datetime.now()
		
		with _request_log_lock:
			cutoff = current_time - timedelta(seconds=RATE_LIMIT_WINDOW)
			_request_log[client_id] = [
				t for t in _request_log[client_id] 
				if t > cutoff
			]
			
			if len(_request_log[client_id]) >= RATE_LIMIT_MAX_REQUESTS:
				logger.warning(f'Rate limit exceeded for {escape_for_html(str(client_id))}')
				return make_response('Rate limit exceeded', 429)
			
			_request_log[client_id].append(current_time)
		
		return f(*args, **kwargs)
	return decorated_function

def validate_cookie_value(value):
	if not isinstance(value, str):
		logger.warning('Cookie value is not a string')
		return None
	
	if len(value) > MAX_COOKIE_VALUE_LENGTH:
		logger.warning('Cookie value exceeds maximum length')
		return None
	
	if not ALLOWED_COOKIE_PATTERN.match(value):
		logger.warning('Invalid cookie value format detected')
		return None
	
	return value

def validate_cookie_name(name):
	if not isinstance(name, str):
		logger.warning('Cookie name is not a string')
		return False
	
	if not VALID_COOKIE_NAME_PATTERN.match(name):
		logger.warning('Invalid cookie name format detected')
		return False
	
	return True

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	@rate_limit
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', secrets.token_hex(16),
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	@rate_limit
	def BenchmarkTest00064_post():
		RESPONSE = ""

		param = request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied")
		
		validated_param = validate_cookie_value(param)
		if validated_param is None:
			logger.warning('Cookie validation failed')
			return make_response('Invalid cookie', 400)
		
		try:
			param = urllib.parse.unquote_plus(validated_param)
		except Exception as e:
			logger.warning(f'URL decode error: {type(e).__name__}')
			return make_response('Invalid cookie', 400)
		
		if len(param) > MAX_COOKIE_VALUE_LENGTH:
			param = param[:MAX_COOKIE_VALUE_LENGTH]
		
		if not ALLOWED_COOKIE_PATTERN.match(param):
			logger.warning('Decoded parameter contains invalid characters')
			return make_response('Invalid cookie', 400)
		
		bar = escape_for_html(param)

		if not isinstance(bar, str):
			logger.warning('Escaped value is not a string')
			return make_response('Invalid cookie data', 400)

		try:
			input_data = bar.encode('utf-8', errors='ignore')
		except Exception as e:
			logger.warning(f'Encoding error: {type(e).__name__}')
			return make_response('Invalid cookie data', 400)

		try:
			value = input_data.decode('utf-8', errors='ignore')
			if not ALLOWED_COOKIE_PATTERN.match(value):
				raise ValueError('Invalid characters in decoded value')
		except (UnicodeDecodeError, AttributeError, ValueError) as e:
			logger.warning(f'Cookie decode error: {type(e).__name__}')
			return make_response('Invalid cookie data', 400)

		if len(value) > MAX_COOKIE_VALUE_LENGTH:
			value = value[:MAX_COOKIE_VALUE_LENGTH]

		cookie = 'SomeCookie'
		
		if not validate_cookie_name(cookie):
			logger.error('Invalid cookie name detected')
			return make_response('Invalid cookie configuration', 500)

		RESPONSE += (
			f'Created cookie: \'{escape_for_html(cookie)}\' with value \'{escape_for_html(value)}\' and secure flag set to true.'
		)

		response = make_response(RESPONSE)
		response.set_cookie(cookie, value,
			path='/',
			secure=True,
			httponly=True,
			samesite='Strict',
			max_age=COOKIE_MAX_AGE,
			domain=None)

		return response