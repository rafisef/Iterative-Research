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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import os
import sqlite3
import asyncio
import aiofiles
import aiosqlite

def init(app):
	app.secret_key = os.environ.get('APP_SECRET_KEY', 'supersecretkeyforconcurrent')
	app.config['SESSION_TYPE'] = os.environ.get('SESSION_TYPE', 'filesystem')
	app.config['STORAGE_TYPE'] = os.environ.get('STORAGE_TYPE', 'file')
	app.config['DB_PATH'] = os.environ.get('DB_PATH', 'benchmark.db')

	def get_db():
		conn = sqlite3.connect(app.config['DB_PATH'])
		conn.execute('CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY, hash_value TEXT)')
		return conn

	async def get_db_async():
		conn = await aiosqlite.connect(app.config['DB_PATH'])
		await conn.execute('CREATE TABLE IF NOT EXISTS hashes (id INTEGER PRIMARY KEY, hash_value TEXT)')
		return conn

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		session['BenchmarkTest00054'] = 'someSecret'
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		return response
		return BenchmarkTest00054_post()

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(session.get("BenchmarkTest00054", "noCookieValueSupplied"))

		string26833 = ''
		data12 = ''
		copy = string26833
		string26833 = ''
		string26833 += param
		copy += 'SomeOKString'
		bar = copy

		import hashlib, base64
		import io, helpers.utils

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
		storage_type = app.config.get('STORAGE_TYPE', 'file')
		if storage_type == 'db':
			conn = get_db()
			conn.execute('INSERT INTO hashes (hash_value) VALUES (?)', (base64.b64encode(result),))
			conn.commit()
			conn.close()
		else:
			f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
			f.write(f'hash_value={base64.b64encode(result)}\n')
			f.close()
		RESPONSE += (
			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
		)

		return RESPONSE

	@app.route('/benchmark/hash-00/BenchmarkTest00054_async', methods=['POST'])
	async def BenchmarkTest00054_post_async():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(session.get("BenchmarkTest00054", "noCookieValueSupplied"))

		string26833 = ''
		data12 = ''
		copy = string26833
		string26833 = ''
		string26833 += param
		copy += 'SomeOKString'
		bar = copy

		import hashlib, base64
		import io, helpers.utils

		input = ''
		if isinstance(bar, str):
			input = bar.encode('utf-8')
		elif isinstance(bar, io.IOBase):
			input = await asyncio.get_event_loop().run_in_executor(None, bar.read, 1000)

		if len(input) == 0:
			RESPONSE += (
				'Cannot generate hash: Input was empty.'
			)
			return RESPONSE

		hash = hashlib.new('md5')
		hash.update(input)

		result = hash.digest()
		storage_type = app.config.get('STORAGE_TYPE', 'file')
		if storage_type == 'db':
			conn = await get_db_async()
			await conn.execute('INSERT INTO hashes (hash_value) VALUES (?)', (base64.b64encode(result),))
			await conn.commit()
			await conn.close()
		else:
			async with aiofiles.open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a') as f:
				await f.write(f'hash_value={base64.b64encode(result)}\n')
		RESPONSE += (
			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
		)

		return RESPONSE