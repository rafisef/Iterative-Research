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
from urllib.parse import urlparse, urlunparse
import urllib.parse
import base64
import secrets

ALLOWED_HOST = 'localhost:5000'
ALLOWED_SCHEME = 'https'
SAFE_REDIRECT = 'https://localhost:5000/'

def init(app):

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		token = secrets.token_urlsafe(32)
		session['redirect_token'] = token
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', token,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		cookie_val = request.cookies.get("BenchmarkTest00067", "")
		session_token = session.get('redirect_token', '')
		if not secrets.compare_digest(cookie_val, session_token):
			return redirect(SAFE_REDIRECT, code=302)
		param = urllib.parse.unquote_plus(cookie_val)
		try:
			tmp = base64.b64decode(param, validate=True)
			bar = tmp.decode('utf-8', errors='strict')
		except Exception:
			bar = SAFE_REDIRECT

		parsed = urlparse(bar)
		if parsed.scheme != ALLOWED_SCHEME or parsed.netloc != ALLOWED_HOST:
			bar = SAFE_REDIRECT
		else:
			bar = urlunparse((parsed.scheme, parsed.netloc, parsed.path or '/', '', '', ''))
		session.pop('redirect_token', None)
		return redirect(bar, code=302)