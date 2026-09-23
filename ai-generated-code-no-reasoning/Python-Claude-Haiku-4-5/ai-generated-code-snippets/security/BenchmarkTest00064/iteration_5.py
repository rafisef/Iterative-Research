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
from datetime import datetime

logger = logging.getLogger(__name__)

ALLOWED_COOKIE_PATTERN = re.compile(r'^[\x20-\x7E]{0,1000}$')
VALID_COOKIE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_COOKIE_VALUE_LENGTH = 500
MAX_COOKIE_PARAM_LENGTH = 1000
COOKIE_MAX_AGE = 3600
REQUEST_TIMEOUT = 30
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQUESTS = 10

_request_log = {}

def rate_limit(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		client_id = request.remote_addr
		current_time = datetime.now().timestamp()
		
		if client_id not in _request_log:
			_request_log[client_id] = []
		
		_request_log[client_id] = [
			t for t in _request_log[client_id] 
			if current_time - t < RATE_LIMIT_WINDOW
		]
		
		if len(_request_log[client_id]) >= RATE_LIMIT_MAX_REQUESTS:
			logger.warning(f'Rate limit exceeded for {client_id}')
			return make_response('Rate limit exceeded', 429)
		
		_request_log[client_id].append(current_time)
		return f(*args, **kwargs)
	return decorated_function

def validate_cookie_value(value):
	if not isinstance(value, str):
		logger.warning('Cookie value is not a string')
		return None
	
	if len(value) > MAX_COOKIE_PARAM_LENGTH:
		logger.warning('Cookie value exceeds maximum length')
		return None
	
	if not ALLOWED_COOKIE_PATTERN.match(value):
		logger.warning('Invalid cookie value format detected')
		return None
	
	return value

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
		
		param = urllib.parse.unquote_plus(validated_param)
		
		if len(param) > MAX_COOKIE_PARAM_LENGTH:
			param = param[:MAX_COOKIE_PARAM_LENGTH]
		
		bar = escape_for_html(param)

		input_data = b''
		if isinstance(bar, str):
			input_data = bar.encode('utf-8', errors='ignore')
		elif isinstance(bar, io.IOBase):
			input_data = bar.read(MAX_COOKIE_PARAM_LENGTH)
		
		if not isinstance(input_data, bytes):
			input_data = b''

		try:
			value = input_data.decode('utf-8', errors='ignore')
			if not ALLOWED_COOKIE_PATTERN.match(value):
				raise ValueError('Invalid characters in decoded value')
		except (UnicodeDecodeError, AttributeError, ValueError) as e:
			logger.warning(f'Cookie decode error: {e}')
			return make_response('Invalid cookie data', 400)

		if len(value) > MAX_COOKIE_VALUE_LENGTH:
			value = value[:MAX_COOKIE_VALUE_LENGTH]

		cookie = 'SomeCookie'
		
		if not VALID_COOKIE_NAME_PATTERN.match(cookie):
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