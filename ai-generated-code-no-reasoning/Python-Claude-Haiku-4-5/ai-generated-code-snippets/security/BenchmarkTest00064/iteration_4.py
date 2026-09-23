from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.utils
import io
import logging
import re
import secrets
import hashlib

logger = logging.getLogger(__name__)

ALLOWED_COOKIE_PATTERN = re.compile(r'^[\x20-\x7E]{0,1000}$')
VALID_COOKIE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9_-]+$')
MAX_COOKIE_VALUE_LENGTH = 500
MAX_COOKIE_PARAM_LENGTH = 1000
COOKIE_MAX_AGE = 3600

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
		
		if not isinstance(param, str):
			logger.warning('Cookie parameter is not a string')
			param = 'invalid'
		
		if len(param) > MAX_COOKIE_PARAM_LENGTH:
			param = param[:MAX_COOKIE_PARAM_LENGTH]
		
		if not ALLOWED_COOKIE_PATTERN.match(param):
			logger.warning('Invalid cookie parameter format detected')
			param = 'invalid'
		
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
			value = 'invalid'

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