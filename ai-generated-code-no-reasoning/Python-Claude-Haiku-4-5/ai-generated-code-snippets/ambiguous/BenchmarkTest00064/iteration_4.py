from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse


def init(app):
	BENCHMARK_TEST_NAME = 'BenchmarkTest00064'
	BENCHMARK_ROUTE = f'/benchmark/securecookie-00/{BENCHMARK_TEST_NAME}'
	SECURE_COOKIE_MAX_AGE = 180
	SECURE_COOKIE_DOMAIN = 'localhost'
	RESPONSE_COOKIE_NAME = 'SomeCookie'

	@app.route(BENCHMARK_ROUTE, methods=['GET'])
	def benchmark_get():
		response = make_response(render_template(f'web/securecookie-00/{BENCHMARK_TEST_NAME}.html'))
		response.set_cookie(
			BENCHMARK_TEST_NAME,
			'whatever',
			max_age=SECURE_COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain=SECURE_COOKIE_DOMAIN
		)
		return response

	@app.route(BENCHMARK_ROUTE, methods=['POST'])
	def benchmark_post():
		cookie_value = request.cookies.get(BENCHMARK_TEST_NAME, 'noCookieValueSupplied')
		decoded_value = urllib.parse.unquote_plus(cookie_value)
		sanitized_value = escape_for_html(decoded_value)
		
		if not isinstance(sanitized_value, str):
			sanitized_value = ''

		response_text = f'Created cookie: \'{RESPONSE_COOKIE_NAME}\' with value \'{escape_for_html(sanitized_value)}\' and secure flag set to false.'
		response = make_response(response_text)
		response.set_cookie(
			RESPONSE_COOKIE_NAME,
			sanitized_value,
			path=request.path,
			secure=False,
			httponly=True
		)

		return response