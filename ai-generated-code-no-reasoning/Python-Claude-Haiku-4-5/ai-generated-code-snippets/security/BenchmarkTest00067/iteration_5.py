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
import re
from typing import Optional
import hashlib
import secrets

logger = logging.getLogger(__name__)

ALLOWED_HOSTS = frozenset({'localhost', 'localhost:5000'})
ALLOWED_SCHEMES = frozenset({'https'})
MAX_URL_LENGTH = 2048
VALID_URL_PATTERN = re.compile(r'^(?:[a-zA-Z][a-zA-Z0-9+.-]*://)?(?:[a-zA-Z0-9._-]+(?::[0-9]+)?)?(?:/[a-zA-Z0-9._~:/?#\[\]@!$&\'()*+,;=-]*)?$')
MAX_COOKIE_VALUE_LENGTH = 4096
RATE_LIMIT_ATTEMPTS = 5
RATE_LIMIT_WINDOW = 300

redirect_attempts = {}

def is_safe_redirect_url(url: Optional[str], request_host: str) -> bool:
	if not url or len(url) > MAX_URL_LENGTH:
		return False
	
	if url.startswith('//'):
		return False
	
	if url.startswith('javascript:') or url.startswith('data:') or url.startswith('vbscript:'):
		return False
	
	if not VALID_URL_PATTERN.match(url):
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
		if not url.startswith('/'):
			return False
		return True
	
	return True

def check_rate_limit(identifier: str) -> bool:
	import time
	current_time = time.time()
	
	if identifier not in redirect_attempts:
		redirect_attempts[identifier] = []
	
	redirect_attempts[identifier] = [
		timestamp for timestamp in redirect_attempts[identifier]
		if current_time - timestamp < RATE_LIMIT_WINDOW
	]
	
	if len(redirect_attempts[identifier]) >= RATE_LIMIT_ATTEMPTS:
		return False
	
	redirect_attempts[identifier].append(current_time)
	return True

def validate_cookie_signature(cookie_value: str, signature: str) -> bool:
	try:
		expected_signature = hashlib.sha256(cookie_value.encode('utf-8')).hexdigest()
		return secrets.compare_digest(signature, expected_signature)
	except Exception:
		return False

def init(app):

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		cookie_value = 'https%3A%2F%2Flocalhost%3A5000%2F'
		cookie_signature = hashlib.sha256(cookie_value.encode('utf-8')).hexdigest()
		
		response.set_cookie('BenchmarkTest00067', cookie_value,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain='localhost')
		response.set_cookie('BenchmarkTest00067_sig', cookie_signature,
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

		client_ip = request.remote_addr
		if not check_rate_limit(client_ip):
			logger.warning(f"Rate limit exceeded for IP: {client_ip}")
			return RESPONSE

		try:
			param = request.cookies.get("BenchmarkTest00067")
			signature = request.cookies.get("BenchmarkTest00067_sig")
			
			if not param or not signature:
				logger.warning("Missing required cookie or signature")
				return RESPONSE
			
			if len(param) > MAX_COOKIE_VALUE_LENGTH:
				logger.warning("Cookie value exceeds maximum length")
				return RESPONSE
			
			if not validate_cookie_signature(param, signature):
				logger.warning("Cookie signature validation failed")
				return RESPONSE
			
			param = urllib.parse.unquote_plus(param)
		except Exception as e:
			logger.warning(f"Cookie parsing failed: {e}")
			return RESPONSE

		try:
			if not isinstance(param, str) or not param:
				return RESPONSE
			
			tmp = base64.b64encode(param.encode('utf-8'))
			bar = base64.b64decode(tmp).decode('utf-8')
			
			if not isinstance(bar, str) or not bar:
				return RESPONSE
		except Exception as e:
			logger.warning(f"Base64 encoding/decoding failed: {e}")
			return RESPONSE

		request_host = request.host
		if not is_safe_redirect_url(bar, request_host):
			logger.warning(f"Unsafe redirect attempt detected: {bar}")
			return RESPONSE

		return flask.redirect(bar, code=302)