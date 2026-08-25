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
from werkzeug.utils import secure_filename
import os
import urllib.parse
import codecs
import helpers.utils

def init(app):

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get():
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=60*3,
			secure=True,
			httponly=True,
			path=request.path,
			domain='localhost',
			samesite='Strict')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))

		bar = secure_filename(os.path.basename(param))
		base_dir = os.path.abspath(helpers.utils.TESTFILES_DIR)
		file_path = os.path.abspath(os.path.join(base_dir, bar))

		if os.path.commonpath([file_path, base_dir]) != base_dir:
			return "Invalid file path"

		try:
			with codecs.open(file_path,'r','utf-8') as fileTarget:

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
		except Exception:
			RESPONSE += (
				"Error accessing file."
			)

		return RESPONSE