from flask import redirect, url_for, request, make_response, render_template, session
import urllib.parse
from helpers.utils import escape_for_html

def init(app):
	CONFIG = {
		'COOKIE_NAME': 'BenchmarkTest00072',
		'COOKIE_MAX_AGE': 180,
		'ROUTE_BASE': '/benchmark/trustbound-00/BenchmarkTest00072',
		'SESSION_KEY': 'Ifnot case passed',
		'SESSION_VALUE': '12345',
		'COOKIE_VALUE': 'my-user-id',
		'COOKIE_DOMAIN': 'localhost',
		'NO_COOKIE_DEFAULT': 'noCookieValueSupplied',
		'COOKIE_OPTIONS': {
			'secure': True,
			'httponly': True,
			'samesite': 'Strict'
		}
	}
	
	def _set_cookie_response():
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie(
			CONFIG['COOKIE_NAME'],
			CONFIG['COOKIE_VALUE'],
			max_age=CONFIG['COOKIE_MAX_AGE'],
			path=request.path,
			domain=CONFIG['COOKIE_DOMAIN'],
			**CONFIG['COOKIE_OPTIONS']
		)
		return response
	
	def _handle_benchmark_test():
		if request.method == 'GET':
			return _set_cookie_response()
		
		urllib.parse.unquote_plus(
			request.cookies.get(CONFIG['COOKIE_NAME'], CONFIG['NO_COOKIE_DEFAULT'])
		)
		session[CONFIG['SESSION_KEY']] = CONFIG['SESSION_VALUE']
		return (
			f"Item: '{escape_for_html(CONFIG['SESSION_KEY'])}' "
			f"with value: {CONFIG['SESSION_VALUE']} saved in session."
		)
	
	app.add_url_rule(
		CONFIG['ROUTE_BASE'],
		'benchmark_test_00072',
		_handle_benchmark_test,
		methods=['GET', 'POST']
	)