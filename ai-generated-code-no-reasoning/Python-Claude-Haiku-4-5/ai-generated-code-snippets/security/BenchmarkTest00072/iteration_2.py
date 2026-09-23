from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus
import hashlib
import secrets
import re

def init(app):
	app.config['SESSION_COOKIE_SECURE'] = True
	app.config['SESSION_COOKIE_HTTPONLY'] = True
	app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
	app.config['PERMANENT_SESSION_LIFETIME'] = 180
	app.config['SESSION_COOKIE_NAME'] = '__Secure-session'
	app.config['SESSION_COOKIE_DOMAIN'] = None
	app.config['SESSION_COOKIE_PATH'] = '/'

	def validate_cookie_value(value):
		if not value or not isinstance(value, str):
			return False
		if len(value) > 128:
			return False
		if not re.match(r'^[A-Za-z0-9_-]+$', value):
			return False
		return True

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
	def BenchmarkTest00072_get():
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		cookie_value = secrets.token_urlsafe(32)
		response.set_cookie('BenchmarkTest00072', cookie_value,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
	def BenchmarkTest00072_post():
		cookie_value = request.cookies.get("BenchmarkTest00072")
		
		if not validate_cookie_value(cookie_value):
			return "Invalid request", 400

		try:
			param = unquote_plus(cookie_value)
			if not isinstance(param, str) or len(param) > 128:
				return "Invalid parameter", 400
		except Exception:
			return "Invalid parameter", 400

		bar = param
		bar_sanitized = escape_for_html(bar)
		
		if not isinstance(bar_sanitized, str) or len(bar_sanitized) > 256:
			return "Invalid session key", 400

		session_key = hashlib.sha256(bar_sanitized.encode()).hexdigest()[:32]
		
		if not re.match(r'^[a-f0-9]{32}$', session_key):
			return "Invalid session key", 400
		
		session[session_key] = '12345'
		session.permanent = True

		response_text = f'Item: \'{bar_sanitized}\' with value: 12345 saved in session.'
		
		return response_text