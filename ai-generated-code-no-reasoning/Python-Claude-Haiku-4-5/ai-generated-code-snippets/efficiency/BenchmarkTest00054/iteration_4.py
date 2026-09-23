from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import hashlib
import base64

_COOKIE_NAME = 'BenchmarkTest00054'
_COOKIE_MAX_AGE = 180
_COOKIE_DOMAIN = 'localhost'
_APPEND_STRING = 'SomeOKString'
_PASSWORD_FILE = f'{TESTFILES_DIR}/passwordFile.txt'

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie(_COOKIE_NAME, 'someSecret',
			max_age=_COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain=_COOKIE_DOMAIN)
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
		bar = param + _APPEND_STRING
		input_data = bar.encode('utf-8')
		encoded_hash = base64.b64encode(hashlib.md5(input_data).digest()).decode('utf-8')
		
		with open(_PASSWORD_FILE, 'a') as f:
			f.write(f'hash_value={encoded_hash}\n')

		return f'Sensitive value \'{escape_for_html(bar)}\' hashed and stored.'