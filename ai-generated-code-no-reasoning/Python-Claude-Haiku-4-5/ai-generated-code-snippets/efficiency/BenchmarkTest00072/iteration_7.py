from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import urllib.parse

def init(app):
	PATH = '/benchmark/trustbound-00/BenchmarkTest00072'
	COOKIE_NAME = 'BenchmarkTest00072'
	SESSION_KEY = "Ifnot case passed"
	SESSION_VALUE = '12345'
	RESPONSE_TEMPLATE = 'web/trustbound-00/BenchmarkTest00072.html'
	COOKIE_CONFIG = {
		'max_age': 180,
		'secure': True,
		'path': PATH,
		'domain': 'localhost'
	}
	ESCAPED_KEY = escape_for_html(SESSION_KEY)
	SUCCESS_MESSAGE = f'Item: \'{ESCAPED_KEY}\' with value: {SESSION_VALUE} saved in session.'

	@app.route(PATH, methods=['GET', 'POST'])
	def BenchmarkTest00072():
		if request.method == 'GET':
			response = make_response(render_template(RESPONSE_TEMPLATE))
			response.set_cookie(COOKIE_NAME, 'my-user-id', **COOKIE_CONFIG)
			return response
		session[SESSION_KEY] = SESSION_VALUE
		return SUCCESS_MESSAGE