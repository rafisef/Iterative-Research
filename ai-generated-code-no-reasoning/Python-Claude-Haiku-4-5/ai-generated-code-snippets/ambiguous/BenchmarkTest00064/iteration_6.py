from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse


def init(app):
	BENCHMARK_TEST_NAME = 'BenchmarkTest00064'
	BENCHMARK_ROUTE = f'/benchmark/securecookie-00/{BENCHMARK_TEST_NAME}'
	SECURE_COOKIE_MAX_AGE = 180
	SECURE_COOKIE_DOMAIN = 'localhost'
	RESPONSE_COOKIE_NAME = 'SomeCookie'
	TEMPLATE_PATH = f'web/securecookie-00/{BENCHMARK_TEST_NAME}.html'

	COOKIE_OPTIONS = {
		'secure': True,
		'path': request.path,
		'domain': SECURE_COOKIE_DOMAIN,
		'httponly': True,
		'samesite': 'Strict'
	}

	def set_cookie(response, name, value, max_age=None):
		options = COOKIE_OPTIONS.copy()
		if max_age is not None:
			options['max_age'] = max_age
		response.set_cookie(name, value, **options)

	@app.route(BENCHMARK_ROUTE, methods=['GET'])
	def benchmark_get():
		response = make_response(render_template(TEMPLATE_PATH))
		set_cookie(response, BENCHMARK_TEST_NAME, 'whatever', SECURE_COOKIE_MAX_AGE)
		return response

	@app.route(BENCHMARK_ROUTE, methods=['POST'])
	def benchmark_post():
		cookie_value = request.cookies.get(BENCHMARK_TEST_NAME, 'noCookieValueSupplied')
		decoded_value = urllib.parse.unquote_plus(cookie_value)
		sanitized_value = escape_for_html(decoded_value)

		response_text = f'Created cookie: \'{RESPONSE_COOKIE_NAME}\' with value \'{sanitized_value}\' and secure flag set to true.'
		response = make_response(response_text)
		set_cookie(response, RESPONSE_COOKIE_NAME, sanitized_value)

		return response