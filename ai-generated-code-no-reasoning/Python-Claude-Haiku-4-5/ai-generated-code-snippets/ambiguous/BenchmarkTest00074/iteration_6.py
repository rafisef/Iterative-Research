import urllib.parse
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):
	COOKIE_CONFIG = {
		'max_age': 180,
		'secure': True,
		'domain': 'localhost',
		'httponly': True,
		'samesite': 'Strict'
	}
	COOKIE_NAME = 'BenchmarkTest00074'
	ROUTE_PATH = '/benchmark/codeinj-00/BenchmarkTest00074'
	COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'

	@app.route(ROUTE_PATH, methods=['GET', 'POST'])
	def benchmark_test_00074():
		if request.method == 'GET':
			response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
			response.set_cookie(
				COOKIE_NAME,
				COOKIE_VALUE,
				path=request.path,
				**COOKIE_CONFIG
			)
			return response
		
		param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, "noCookieValueSupplied"))
		
		try:
			exec(param)
			return "Code executed successfully"
		except Exception as e:
			return f'Error executing statement \'{escape_for_html(param)}\': {escape_for_html(str(e))}'