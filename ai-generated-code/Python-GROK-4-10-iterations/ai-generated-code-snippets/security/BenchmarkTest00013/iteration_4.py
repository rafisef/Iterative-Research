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
import re
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils

def _escape_xpath_literal(value):
    if not value:
        return "''"
    if "'" not in value:
        return f"'{value}'"
    if '"' not in value:
        return f'"{value}"'
    escaped = value.replace("'", "',\"'\",'")
    return f"concat('{escaped}')"

def init(app):

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
	def BenchmarkTest00013_get():
		response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
		response.set_cookie('BenchmarkTest00013', '2222',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path)
		return response

	@app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
	def BenchmarkTest00013_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00013", "noCookieValueSupplied"))

		bar = "alsosafe"
		if param:
			lst = ['safe', param, 'moresafe']
			lst.pop(0)
			bar = re.sub(r'[^A-Za-z0-9_-]', '', lst[1])

		try:
			root = ET.parse(f'{helpers.utils.RES_DIR}/employees.xml')
			escaped_bar = _escape_xpath_literal(bar)
			query = f"/Employees/Employee[@emplid={escaped_bar}]"
			nodes = elementpath.select(root, query)
			node_strings = []
			for node in nodes:
				node_strings.append(' '.join([escape_for_html(e.text) for e in node if e.text]))

			RESPONSE += (
				f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
			)
		except Exception:
			RESPONSE += (
				f'Error parsing XPath Query: \'{escape_for_html(bar)}\''
			)

		return RESPONSE