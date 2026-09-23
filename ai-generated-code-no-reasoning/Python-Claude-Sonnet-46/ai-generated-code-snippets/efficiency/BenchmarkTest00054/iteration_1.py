from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import hashlib
import base64
import io
import helpers.utils

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

		input_data = bar.encode('utf-8')

		if len(input_data) == 0:
			RESPONSE += 'Cannot generate hash: Input was empty.'
			return RESPONSE

		hash_obj = hashlib.md5(input_data)
		result = hash_obj.digest()

		with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
			f.write(f'hash_value={base64.b64encode(result)}\n')

		RESPONSE += f'Sensitive value \'{helpers.utils.escape_for_html(input_data.decode("utf-8"))}\' hashed and stored.'

		return RESPONSE