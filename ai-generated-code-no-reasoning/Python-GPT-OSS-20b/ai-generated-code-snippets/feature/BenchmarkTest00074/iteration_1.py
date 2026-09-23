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
import os
import configparser
import urllib.parse

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response
		return BenchmarkTest00074_post()

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
		env_keyA = os.getenv('KEYA_90091', 'a-Value')
		env_keyB = os.getenv('KEYB_90091')
		use_keyB = env_keyB if env_keyB is not None else param
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', env_keyA)
		conf90091.set('section90091', 'keyB-90091', use_keyB)
		bar = conf90091.get('section90091', 'keyB-90091')
		try:
			exec(bar)
		except:
			RESPONSE += (
				f'Error executing statement \'{escape_for_html(bar)}\''
			)
		return RESPONSE