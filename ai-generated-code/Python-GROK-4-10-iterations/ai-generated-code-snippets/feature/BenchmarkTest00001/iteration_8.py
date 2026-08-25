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
import urllib.parse
import codecs
import helpers.utils
import os

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=int(os.environ.get('BENCHMARK_COOKIE_MAX_AGE', 60*3)),
			secure=os.environ.get('BENCHMARK_COOKIE_SECURE', 'True').lower() == 'true',
			path=request.path,
			domain=os.environ.get('BENCHMARK_DOMAIN', 'localhost'))
		return response

	def _BenchmarkTest00001_post_sync():
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))
		bar = param
		testfiles_dir = os.environ.get('TESTFILES_DIR', helpers.utils.TESTFILES_DIR)
		try:
			fileTarget = codecs.open(f'{testfiles_dir}/{bar}','r','utf-8')
			RESPONSE += (
				f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
			)
			RESPONSE += (
				" And file already exists."
			)
		except FileNotFoundError:
			RESPONSE += (
				" But file doesn't exist yet."
			)
		return RESPONSE

	async def _BenchmarkTest00001_post_async():
		return _BenchmarkTest00001_post_sync()

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		return asyncio.run(_BenchmarkTest00001_post_async())

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001/async', methods=['POST'])
	async def BenchmarkTest00001_post_async():
		return await _BenchmarkTest00001_post_async()