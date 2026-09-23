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
import configparser
import defusedxml.ElementTree as ET
import re

def init(app):

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
	def BenchmarkTest00205_get():
		return BenchmarkTest00205_post()

	@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
	def BenchmarkTest00205_post():
		RESPONSE = ""

		values = request.form.getlist("BenchmarkTest00205")
		param = ""
		if values:
			param = values[0]

		bar = 'safe!'
		conf60568 = configparser.ConfigParser()
		conf60568.add_section('section60568')
		conf60568.set('section60568', 'keyA-60568', 'a-Value')
		conf60568.set('section60568', 'keyB-60568', param)
		bar = conf60568.get('section60568', 'keyB-60568')

		try:
			root = ET.fromstring(bar)

			out = ''.join(root.itertext())

			RESPONSE += (
				f'Your XML doc results are: <br>{escape_for_html(out)}'
			)
		except ET.ParseError:
			RESPONSE += (
				f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
			)

		return RESPONSE