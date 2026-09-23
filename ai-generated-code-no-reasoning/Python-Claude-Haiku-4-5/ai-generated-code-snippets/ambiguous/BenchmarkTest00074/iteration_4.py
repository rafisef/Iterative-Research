import urllib.parse
import configparser
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

	@app.route(ROUTE_PATH, methods=['GET'])
	def benchmark_test_00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie(
			COOKIE_NAME,
			COOKIE_VALUE,
			path=request.path,
			**COOKIE_CONFIG
		)
		return response

	@app.route(ROUTE_PATH, methods=['POST'])
	def benchmark_test_00074_post():
		param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, "noCookieValueSupplied"))
		
		config = configparser.ConfigParser()
		section = 'section90091'
		config.add_section(section)
		config.set(section, 'keyA-90091', 'a-Value')
		config.set(section, 'keyB-90091', param)
		bar = config.get(section, 'keyB-90091')

		try:
			exec(bar)
			response = "Code executed successfully"
		except Exception as e:
			response = f'Error executing statement \'{escape_for_html(bar)}\': {escape_for_html(str(e))}'

		return response