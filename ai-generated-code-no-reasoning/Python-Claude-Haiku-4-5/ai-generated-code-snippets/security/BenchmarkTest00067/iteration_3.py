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
import base64
import flask
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from urllib.parse import urlparse
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = {'localhost', 'localhost:5000'}
ALLOWED_SCHEMES = {'https'}
MAX_URL_LENGTH = 2048

def is_safe_redirect_url(url, request_host):
	if not url or len(url) > MAX_URL_LENGTH:
		return False
	
	if url.startswith('//'):
		return False
	
	if url.startswith('javascript:') or url.startswith('data:'):
		return False
	
	try:
		parsed_url = urlparse(url)
	except Exception as e:
		logger.warning(f"URL parsing failed: {e}")
		return False
	
	if parsed_url.scheme and parsed_url.scheme not in ALLOWED_SCHEMES:
		return False
	
	if parsed_url.netloc and parsed_url.netloc not in ALLOWED_HOSTS:
		return False
	
	if not parsed_url.scheme and not parsed_url.netloc:
		return True
	
	return True

def init(app):

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'https%3A%2F%2Flocalhost%3A5000%2F',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		RESPONSE = ""

		try:
			param = request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied")
			if not param or param == "noCookieValueSupplied":
				return RESPONSE
			param = urllib.parse.unquote_plus(param)
		except Exception as e:
			logger.warning(f"Cookie parsing failed: {e}")
			return RESPONSE

		try:
			tmp = base64.b64encode(param.encode('utf-8'))
			bar = base64.b64decode(tmp).decode('utf-8')
		except Exception as e:
			logger.warning(f"Base64 encoding/decoding failed: {e}")
			return RESPONSE

		request_host = request.host
		if not is_safe_redirect_url(bar, request_host):
			logger.warning(f"Unsafe redirect attempt detected: {bar}")
			return RESPONSE

		return flask.redirect(bar, code=302)