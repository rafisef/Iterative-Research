from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus
import hashlib
import secrets
import re
from functools import wraps
from werkzeug.security import safe_str_cmp

def init(app):
	app.config['SESSION_COOKIE_SECURE'] = True
	app.config['SESSION_COOKIE_HTTPONLY'] = True
	app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'
	app.config['PERMANENT_SESSION_LIFETIME'] = 180
	app.config['SESSION_COOKIE_NAME'] = '__Secure-session'
	app.config['SESSION_COOKIE_DOMAIN'] = None
	app.config['SESSION_COOKIE_PATH'] = '/'
	app.config['SESSION_REFRESH_EACH_REQUEST'] = True
	app.config['PREFERRED_URL_SCHEME'] = 'https'

	def validate_cookie_value(value):
		if not value or not isinstance(value, str):
			return False
		if len(value) > 128:
			return False
		if not re.match(r'^[A-Za-z0-9_-]+$', value):
			return False
		return True

	def rate_limit_check(key):
		if 'rate_limit' not in session:
			session['rate_limit'] = {}
		
		now = secrets.randbits(32)
		if key not in session['rate_limit']:
			session['rate_limit'][key] = []
		
		session['rate_limit'][key] = [t for t in session['rate_limit'][key] if t > now - 60]
		
		if len(session['rate_limit'][key]) >= 10:
			return False
		
		session['rate_limit'][key].append(now)
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
		session['csrf_token'] = secrets.token_urlsafe(32)
		return response

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
	def BenchmarkTest00072_post():
		if not request.is_secure:
			return "Insecure request", 400

		if 'csrf_token' not in session or not request.form.get('csrf_token'):
			return "Missing CSRF token", 400

		if not safe_str_cmp(session.get('csrf_token', ''), request.form.get('csrf_token', '')):
			return "Invalid CSRF token", 403

		if not rate_limit_check('benchmark_test'):
			return "Rate limit exceeded", 429

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
		
		session_value = secrets.token_urlsafe(16)
		session[session_key] = session_value
		session.permanent = True
		session.modified = True

		response_text = f'Item: \'{bar_sanitized}\' with value: {session_value} saved in session.'
		
		return response_text