from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import urllib.parse
import hashlib
import base64

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
		bar = b'SomeOKString'

		if len(bar) == 0:
			return (
				'Cannot generate hash: Input was empty.'
			)

		hash_obj = hashlib.md5()
		hash_obj.update(bar)

		result = hash_obj.digest()
		with open(f'{TESTFILES_DIR}/passwordFile.txt', 'a') as f:
			f.write(f'hash_value={base64.b64encode(result)}\n')
		return (
			f'Sensitive value \'{escape_for_html(bar.decode('utf-8'))}\' hashed and stored.'
		)