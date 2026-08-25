'''
OWASP Benchmark for Python v0.2

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

import logging
import urllib.parse
from pathlib import Path
from typing import Any

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR

logger = logging.getLogger(__name__)


def init(app: Any) -> None:

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
	def BenchmarkTest00001_get() -> Any:
		response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
		response.set_cookie('BenchmarkTest00001', 'Filename',
			max_age=180,
			secure=True,
			httponly=True,
			path=request.path,
			domain='localhost',
			samesite='Strict')
		return response

	@app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
	def BenchmarkTest00001_post() -> str:
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))
		bar = param
		file_path = Path(TESTFILES_DIR) / bar
		response: list[str] = []

		try:
			with file_path.open('r', encoding='utf-8') as file_target:
				response.append(f"Access to file: '{escape_for_html(str(file_target.name))}' created.")
				response.append(" And file already exists.")
		except FileNotFoundError:
			response.append(" But file doesn't exist yet.")
		except OSError as e:
			logger.error("File access error", exc_info=True)
			response.append(f"Error accessing file: {escape_for_html(str(e))}")

		return ''.join(response)