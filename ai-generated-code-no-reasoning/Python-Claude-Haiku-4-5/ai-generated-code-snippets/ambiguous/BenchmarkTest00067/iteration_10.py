from flask import redirect, url_for, request, make_response, render_template
from urllib.parse import urlparse, unquote_plus


def init(app):
	COOKIE_NAME = 'BenchmarkTest00067'
	COOKIE_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
	COOKIE_CONFIG = {
		'max_age': 180,
		'path': '/benchmark/redirect-00/BenchmarkTest00067',
		'domain': 'localhost',
		'secure': True,
		'httponly': True,
		'samesite': 'Strict',
	}
	
	ALLOWED_SCHEMES = {'http', 'https'}
	DEFAULT_COOKIE = 'noCookieValueSupplied'
	ROUTE_PATH = '/benchmark/redirect-00/BenchmarkTest00067'
	TEMPLATE = 'web/redirect-00/BenchmarkTest00067.html'

	def is_safe_url(url):
		try:
			parsed = urlparse(url)
			return parsed.scheme in ALLOWED_SCHEMES and bool(parsed.netloc)
		except (ValueError, TypeError):
			return False

	@app.route(ROUTE_PATH, methods=['GET', 'POST'])
	def BenchmarkTest00067():
		if request.method == 'GET':
			response = make_response(render_template(TEMPLATE))
			response.set_cookie(COOKIE_NAME, COOKIE_VALUE, **COOKIE_CONFIG)
			return response

		cookie_value = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE)
		param = unquote_plus(cookie_value)

		if is_safe_url(param):
			return redirect(param, code=302)
		return redirect(url_for('BenchmarkTest00067'), code=302)