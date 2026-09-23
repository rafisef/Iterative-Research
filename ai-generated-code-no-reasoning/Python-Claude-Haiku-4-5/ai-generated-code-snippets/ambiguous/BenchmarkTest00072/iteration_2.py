from flask import redirect, url_for, request, make_response, render_template, session
import urllib.parse
from helpers.utils import escape_for_html

def init(app):
	COOKIE_NAME = 'BenchmarkTest00072'
	COOKIE_MAX_AGE = 60 * 3
	ROUTE_BASE = '/benchmark/trustbound-00/BenchmarkTest00072'
	
	@app.route(ROUTE_BASE, methods=['GET'])
	def benchmark_test_00072_get():
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie(
			COOKIE_NAME,
			'my-user-id',
			max_age=COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain='localhost'
		)
		return response

	@app.route(ROUTE_BASE, methods=['POST'])
	def benchmark_test_00072_post():
		param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, "noCookieValueSupplied"))
		bar = "Ifnot case passed"
		session[bar] = '12345'
		response = f'Item: \'{escape_for_html(bar)}\' with value: 12345 saved in session.'
		return response