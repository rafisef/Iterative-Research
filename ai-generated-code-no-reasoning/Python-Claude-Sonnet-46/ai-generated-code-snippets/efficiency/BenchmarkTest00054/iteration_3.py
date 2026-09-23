from flask import request, make_response, render_template
import helpers.utils

_FIXED_INPUT = b'SomeOKString'

import hashlib, base64
from helpers.utils import escape_for_html

_FIXED_HASH = base64.b64encode(hashlib.md5(_FIXED_INPUT).digest())
_FIXED_RESPONSE = f"Sensitive value '{escape_for_html(_FIXED_INPUT.decode())}' hashed and stored."
_HASH_LINE = f'hash_value={_FIXED_HASH}\n'
_TESTFILES_DIR = helpers.utils.TESTFILES_DIR
_PASSWORD_FILE = f'{_TESTFILES_DIR}/passwordFile.txt'

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		with open(_PASSWORD_FILE, 'a') as f:
			f.write(_HASH_LINE)
		return _FIXED_RESPONSE