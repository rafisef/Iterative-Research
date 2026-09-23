from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse


def init(app):
	BENCHMARK_TEST_NAME = 'BenchmarkTest00064'
	BENCHMARK_ROUTE = f'/benchmark/securecookie-00/{BENCHMARK_TEST_NAME}'
	RESPONSE_COOKIE_NAME = 'SomeCookie'
	TEMPLATE_PATH = f'web/securecookie-00/{BENCHMARK_TEST_NAME}.html'

	COOKIE_OPTIONS = {
		'secure': True,
		'domain': 'localhost',
		'httponly': True,
		'samesite': 'Strict',
		'max_age': 180
	}

	def set_cookie(response, name, value):
		response.set_cookie(name, value, **COOKIE_OPTIONS)

	def get_sanitized_cookie_value(cookie_name, default='noCookieValueSupplied'):
		cookie_value = request.cookies.get(cookie_name, default)
		return escape_for_html(urllib.parse.unquote_plus(cookie_value))

	@app.route(BENCHMARK_ROUTE, methods=['GET', 'POST'])
	def benchmark():
		if request.method == 'GET':
			response = make_response(render_template(TEMPLATE_PATH))
			set_cookie(response, BENCHMARK_TEST_NAME, 'whatever')
			return response

		sanitized_value = get_sanitized_cookie_value(BENCHMARK_TEST_NAME)
		message = f'Created cookie: \'{RESPONSE_COOKIE_NAME}\' with value \'{sanitized_value}\' and secure flag set to true.'
		
		response = make_response(message)
		set_cookie(response, RESPONSE_COOKIE_NAME, sanitized_value)

		return response