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
import asyncio
import hashlib, base64
import io, helpers.utils
import urllib.parse
import sqlite3
import os
import threading

STORAGE_TYPE = os.environ.get('STORAGE_TYPE', 'file')
DOMAIN = os.environ.get('DOMAIN', 'localhost')
COOKIE_MAX_AGE = int(os.environ.get('COOKIE_MAX_AGE', 60*3))
COOKIE_SECURE = os.environ.get('COOKIE_SECURE', 'True').lower() == 'true'
DB_PATH = os.environ.get('DB_PATH', f'{helpers.utils.TESTFILES_DIR}/hashes.db')
FILE_PATH = os.environ.get('FILE_PATH', f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt')
LOCK = threading.Lock()

def init(app):

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=COOKIE_MAX_AGE,
			secure=COOKIE_SECURE,
			path=request.path,
			domain=DOMAIN)
		return response
		return BenchmarkTest00054_post()

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		return asyncio.run(_BenchmarkTest00054_post_async())

	async def _BenchmarkTest00054_post_async():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00054", "noCookieValueSupplied"))

		string26833 = ''
		data12 = ''
		copy = string26833
		string26833 = ''
		string26833 += param
		copy += 'SomeOKString'
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

		hash = hashlib.new('md5')
		hash.update(input)

		result = hash.digest()
		with LOCK:
			if STORAGE_TYPE == 'file':
				f = open(FILE_PATH, 'a')
				f.write(f'hash_value={base64.b64encode(result)}\n')
				RESPONSE += (
					f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
				)
				f.close()
			elif STORAGE_TYPE == 'db':
				conn = sqlite3.connect(DB_PATH)
				c = conn.cursor()
				c.execute('CREATE TABLE IF NOT EXISTS hashes (hash_value TEXT)')
				c.execute('INSERT INTO hashes VALUES (?)', (base64.b64encode(result),))
				conn.commit()
				conn.close()
				RESPONSE += (
					f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
				)

		return RESPONSE