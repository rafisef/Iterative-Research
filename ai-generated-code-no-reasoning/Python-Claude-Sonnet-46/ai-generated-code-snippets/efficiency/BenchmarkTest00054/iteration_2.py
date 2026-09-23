from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import hashlib
import base64
import helpers.utils

_FIXED_INPUT = b'SomeOKString'
_FIXED_HASH = base64.b64encode(hashlib.md5(_FIXED_INPUT).digest())
_FIXED_RESPONSE = f"Sensitive value '{escape_for_html(_FIXED_INPUT.decode('utf-8'))}' hashed and stored."

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
			f.write(f'hash_value={_FIXED_HASH}\n')
		return _FIXED_RESPONSE