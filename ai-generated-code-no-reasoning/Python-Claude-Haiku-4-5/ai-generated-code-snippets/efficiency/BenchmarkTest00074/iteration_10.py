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

import urllib.parse
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

_COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
_COOKIE_DEFAULTS = {
    'max_age': 180,
    'secure': True,
    'path': '/benchmark/codeinj-00/BenchmarkTest00074',
    'domain': 'localhost'
}
_TEMPLATE = None
_RENDERED_TEMPLATE = None
_EMPTY_GLOBALS = {"__builtins__": {}}

def init(app):
	global _TEMPLATE, _RENDERED_TEMPLATE
	_TEMPLATE = app.jinja_env.get_template('web/codeinj-00/BenchmarkTest00074.html')
	_RENDERED_TEMPLATE = _TEMPLATE.render()

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET', 'POST'])
	def BenchmarkTest00074():
		if request.method == 'GET':
			response = make_response(_RENDERED_TEMPLATE)
			response.set_cookie('BenchmarkTest00074', _COOKIE_VALUE, **_COOKIE_DEFAULTS)
			return response
		
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
		try:
			exec(param, _EMPTY_GLOBALS, _EMPTY_GLOBALS)
			return ""
		except Exception:
			return f'Error executing statement \'{escape_for_html(param)}\''