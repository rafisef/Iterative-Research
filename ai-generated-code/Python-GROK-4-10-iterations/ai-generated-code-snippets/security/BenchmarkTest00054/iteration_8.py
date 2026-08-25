'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import redirect, url_for, request, make_response, render_template
from helpers import utils
import os
import hashlib
import base64
import io
import secrets

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path)
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		RESPONSE = ""

		cookie_val = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")
		if len(cookie_val) > 1024:
			cookie_val = cookie_val[:1024]
		param = utils.unquote_plus(cookie_val)

		string26833 = ''
		data12 = ''
		copy = string26833
		string26833 = ''
		string26833 += param
		copy += 'SomeOKString'
		bar = copy

		input = b''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = bar.read(1000)

		if len(input) == 0:
			RESPONSE += (
				'Cannot generate hash: Input was empty.'
			)
			return RESPONSE

		salt = secrets.token_bytes(16)
		hash = hashlib.pbkdf2_hmac('sha256', input, salt, 100000)
		result = salt + hash
		out_path = f'{utils.TESTFILES_DIR}/passwordFile.txt'
		with open(out_path, 'ab', opener=lambda p, f: os.open(p, f | os.O_APPEND | os.O_CREAT, 0o600)) as f:
			f.write(b'hash_value=' + base64.b64encode(result) + b'\n')
		RESPONSE += (
			f'Sensitive value \'{utils.escape_for_html(input.decode('utf-8', errors='replace'))}\' hashed and stored.'
		)

		return RESPONSE