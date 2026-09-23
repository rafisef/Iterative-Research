from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.utils
import io
import logging
import re

logger = logging.getLogger(__name__)

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
		
		if len(param) > 1000:
			param = param[:1000]
		
		if not isinstance(param, str) or not re.match(r'^[\x20-\x7E]*$', param):
			logger.warning('Invalid cookie parameter format detected')
			param = 'invalid'
		
		bar = helpers.utils.escape_for_html(param)

		input_data = ''
		if isinstance(bar, str):
			input_data = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input_data = bar.read(1000)
		else:
			input_data = b''

		try:
			value = input_data.decode('utf-8')
			if not re.match(r'^[\x20-\x7E]*$', value):
				raise ValueError('Invalid characters in decoded value')
		except (UnicodeDecodeError, AttributeError, ValueError) as e:
			logger.warning(f'Cookie decode error: {e}')
			value = 'invalid'

		if len(value) > 500:
			value = value[:500]

		cookie = 'SomeCookie'
		
		if not re.match(r'^[a-zA-Z0-9_-]+$', cookie):
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
			max_age=3600,
			domain=None)

		return response