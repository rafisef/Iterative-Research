from flask import redirect, url_for, request, make_response, render_template
from functools import wraps
from urllib.parse import urlparse, unquote_plus


def init(app):
	CONFIG = {
		'COOKIE_NAME': 'BenchmarkTest00067',
		'COOKIE_VALUE': 'http%3A%2F%2Flocalhost%3A5000%2F',
		'COOKIE_MAX_AGE': 180,
		'COOKIE_PATH': '/benchmark/redirect-00/BenchmarkTest00067',
		'COOKIE_DOMAIN': 'localhost',
		'DEFAULT_COOKIE': 'noCookieValueSupplied',
		'ALLOWED_SCHEMES': ('http', 'https'),
		'SECURE': True,
		'HTTPONLY': True,
		'SAMESITE': 'Strict',
	}

	def is_safe_url(url):
		try:
			parsed = urlparse(url)
			return parsed.scheme in CONFIG['ALLOWED_SCHEMES'] and bool(parsed.netloc)
		except Exception:
			return False

	def set_redirect_cookie(response):
		response.set_cookie(
			CONFIG['COOKIE_NAME'],
			CONFIG['COOKIE_VALUE'],
			max_age=CONFIG['COOKIE_MAX_AGE'],
			secure=CONFIG['SECURE'],
			path=CONFIG['COOKIE_PATH'],
			domain=CONFIG['COOKIE_DOMAIN'],
			httponly=CONFIG['HTTPONLY'],
			samesite=CONFIG['SAMESITE']
		)
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET', 'POST'])
	def BenchmarkTest00067():
		if request.method == 'GET':
			response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
			return set_redirect_cookie(response)

		cookie_value = request.cookies.get(CONFIG['COOKIE_NAME'], CONFIG['DEFAULT_COOKIE'])
		param = unquote_plus(cookie_value)

		redirect_url = param if is_safe_url(param) else url_for('BenchmarkTest00067')
		return redirect(redirect_url, code=302)