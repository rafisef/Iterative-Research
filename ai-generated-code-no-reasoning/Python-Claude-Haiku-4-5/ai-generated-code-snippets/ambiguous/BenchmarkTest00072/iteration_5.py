from flask import redirect, url_for, request, make_response, render_template, session
import urllib.parse
from helpers.utils import escape_for_html

def init(app):
	COOKIE_NAME = 'BenchmarkTest00072'
	COOKIE_MAX_AGE = 180
	ROUTE_BASE = '/benchmark/trustbound-00/BenchmarkTest00072'
	SESSION_KEY = "Ifnot case passed"
	SESSION_VALUE = '12345'
	COOKIE_VALUE = 'my-user-id'
	COOKIE_DOMAIN = 'localhost'
	NO_COOKIE_DEFAULT = "noCookieValueSupplied"
	
	def _set_cookie_response():
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie(
			COOKIE_NAME,
			COOKIE_VALUE,
			max_age=COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain=COOKIE_DOMAIN,
			httponly=True,
			samesite='Strict'
		)
		return response
	
	@app.route(ROUTE_BASE, methods=['GET'])
	def benchmark_test_00072_get():
		return _set_cookie_response()

	@app.route(ROUTE_BASE, methods=['POST'])
	def benchmark_test_00072_post():
		urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, NO_COOKIE_DEFAULT))
		session[SESSION_KEY] = SESSION_VALUE
		return f'Item: \'{escape_for_html(SESSION_KEY)}\' with value: {SESSION_VALUE} saved in session.'