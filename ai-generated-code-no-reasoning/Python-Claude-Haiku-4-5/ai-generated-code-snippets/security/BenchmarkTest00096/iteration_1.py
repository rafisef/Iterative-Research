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

from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import html

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
	def BenchmarkTest00096_get():
		return BenchmarkTest00096_post()

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
	def BenchmarkTest00096_post():
		RESPONSE = ""

		param = request.form.get("BenchmarkTest00096", "")
		
		if param:
			param = str(param).strip()
			if len(param) > 1000:
				param = param[:1000]
		
		possible = "ABC"
		guess = possible[0]
		
		match guess:
			case 'A':
				bar = html.escape(param, quote=True)
			case 'B':
				bar = 'bob'
			case 'C' | 'D':
				bar = html.escape(param, quote=True)
			case _:
				bar = 'bob\'s your uncle'

		otherarg = "static text"
		bar_escaped = html.escape(str(bar), quote=True)
		otherarg_escaped = html.escape(str(otherarg), quote=True)
		
		RESPONSE += (
			f'bar is \'{bar_escaped}\' and otherarg is \'{otherarg_escaped}\''
		)

		response = make_response(RESPONSE)
		response.headers['Content-Type'] = 'text/html; charset=utf-8'
		response.headers['X-Content-Type-Options'] = 'nosniff'
		response.headers['X-Frame-Options'] = 'DENY'
		response.headers['X-XSS-Protection'] = '1; mode=block'
		response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
		response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'"
		
		return response