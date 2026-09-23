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
import hashlib
import base64
import io
import helpers.utils
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

		if not isinstance(param, str) or len(param) == 0:
			RESPONSE += 'Cannot generate hash: Input was empty.'
			return RESPONSE

		param = param[:1000]

		input_data = ''
		if isinstance(param, str):
			input_data = param.encode('utf-8')
		else:
			RESPONSE += 'Cannot generate hash: Invalid input type.'
			return RESPONSE

		if len(input_data) == 0:
			RESPONSE += 'Cannot generate hash: Input was empty.'
			return RESPONSE

		hash_obj = hashlib.sha256()
		hash_obj.update(input_data)

		result = hash_obj.digest()
		
		try:
			file_path = Path(helpers.utils.TESTFILES_DIR).resolve() / 'passwordFile.txt'
			testfiles_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
			
			if not file_path.resolve().is_relative_to(testfiles_dir):
				raise ValueError("Path traversal attempt detected")
			
			if not testfiles_dir.exists():
				testfiles_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
			
			testfiles_dir.chmod(0o700)
			
			with open(file_path, 'a', encoding='utf-8') as f:
				f.write(f'hash_value={base64.b64encode(result).decode("utf-8")}\n')
			
			file_path.chmod(0o600)
			
			RESPONSE += f'Sensitive value \'{escape_for_html(input_data.decode("utf-8"))}\' hashed and stored.'
		except (IOError, OSError, ValueError) as e:
			logger.error(f"Error processing request: {type(e).__name__}")
			RESPONSE += 'Error processing request.'
			return RESPONSE

		return RESPONSE