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
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))
		bar = param + 'SomeOKString'

		if isinstance(bar, str):
			input_data = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input_data = bar.read(1000)
		else:
			input_data = b''

		if len(input_data) == 0:
			return 'Cannot generate hash: Input was empty.'

		hash_obj = hashlib.md5()
		hash_obj.update(input_data)

		result = hash_obj.digest()
		with open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
			f.write(f'hash_value={base64.b64encode(result).decode("utf-8")}\n')

		return f'Sensitive value \'{escape_for_html(input_data.decode("utf-8"))}\' hashed and stored.'