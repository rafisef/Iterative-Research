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

import asyncio
import os
import urllib.parse
import hashlib
import base64
import io
import json
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import helpers.utils

_config_cache = None

def init(app):
	global _config_cache
	_config_cache = _load_config()
	config = _config_cache

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
	def BenchmarkTest00054_get():
		response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
		response.set_cookie('BenchmarkTest00054', 'someSecret',
			max_age=config['cookie_max_age'],
			secure=config['cookie_secure'],
			path=request.path,
			domain=config['cookie_domain'])
		return response

	@app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
	def BenchmarkTest00054_post():
		return _process_benchmark(config, is_async=False)

	@app.route('/benchmark/hash-00/BenchmarkTest00054/async', methods=['POST'])
	async def BenchmarkTest00054_post_async():
		return await _process_benchmark(config, is_async=True)

	def _process_benchmark(config, is_async=False):
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

		hash = hashlib.new(config['hash_algorithm'])
		hash.update(input)

		result = hash.digest()
		
		if is_async:
			asyncio.run(asyncio.sleep(0))
		
		f = open(f'{helpers.utils.TESTFILES_DIR}/passwordFile.txt', 'a')
		f.write(f'hash_value={base64.b64encode(result)}\n')
		RESPONSE += (
			f'Sensitive value \'{helpers.utils.escape_for_html(input.decode('utf-8'))}\' hashed and stored.'
		)
		f.close()

		return RESPONSE

def _load_config():
	config_file = os.getenv('BENCHMARK_CONFIG_FILE')
	config = {
		'cookie_max_age': 180,
		'cookie_secure': True,
		'cookie_domain': 'localhost',
		'hash_algorithm': 'md5',
	}
	
	if config_file and os.path.isfile(config_file):
		try:
			with open(config_file, 'r') as f:
				file_config = json.load(f)
				config.update(file_config)
		except (json.JSONDecodeError, IOError):
			pass
	
	config['cookie_max_age'] = int(os.getenv('BENCHMARK_COOKIE_MAX_AGE', config['cookie_max_age']))
	config['cookie_secure'] = os.getenv('BENCHMARK_COOKIE_SECURE', str(config['cookie_secure'])).lower() == 'true'
	config['cookie_domain'] = os.getenv('BENCHMARK_COOKIE_DOMAIN', config['cookie_domain'])
	config['hash_algorithm'] = os.getenv('BENCHMARK_HASH_ALGORITHM', config['hash_algorithm'])
	
	return config