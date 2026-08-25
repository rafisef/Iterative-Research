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
from helpers.utils import escape_for_html
import hashlib, base64
import io, helpers.utils
import os

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=60*3,
			secure=True,
			httponly=True, # Added HttpOnly flag for cookies
			samesite='Strict', # Added SameSite attribute for cookies
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		RESPONSE = ""

		param = request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied")

		copy = 'SomeOKString' + param
		bar = copy

		input = ''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = bar.read(1000)

		if len(input) == 0:
			RESPONSE += (
				'Cannot generate hash: Input was empty.'
			)
			return RESPONSE

		# Use a more secure hash algorithm, such as SHA-256
		hash = hashlib.sha256()
		hash.update(input)

		result = hash.digest()
		password_file_path = os.path.join(helpers.utils.TESTFILES_DIR, 'passwordFile.txt')
		with open(password_file_path, 'a') as f:
			f.write(f'hash_value={base64.b64encode(result).decode('utf-8')}\n')
		RESPONSE += (
			f'Sensitive value \'{escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
		)

		return RESPONSE