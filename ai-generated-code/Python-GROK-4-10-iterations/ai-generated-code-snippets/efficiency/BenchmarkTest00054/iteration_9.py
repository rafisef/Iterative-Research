from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import hashlib, base64
import helpers.utils

_input = b'SomeOKString'
_hash = hashlib.md5()
_hash.update(_input)
_result = _hash.digest()
_encoded = base64.b64encode(_result)

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
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

		bar = 'SomeOKString'

		with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
			f.write(f'hash_value={_encoded}\n')
		RESPONSE += (
			f'Sensitive value \'{helpers.utils.escape_for_html(bar)}\' hashed and stored.'
		)

		return RESPONSE