from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import base64


def init(app):
	COOKIE_NAME = 'BenchmarkTest00067'
	COOKIE_VALUE = 'http%3A%2F%2Flocalhost%3A5000%2F'
	COOKIE_MAX_AGE = 60 * 3
	COOKIE_PATH = '/benchmark/redirect-00/BenchmarkTest00067'
	COOKIE_DOMAIN = 'localhost'
	DEFAULT_COOKIE = 'noCookieValueSupplied'

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie(
			COOKIE_NAME,
			COOKIE_VALUE,
			max_age=COOKIE_MAX_AGE,
			secure=True,
			path=COOKIE_PATH,
			domain=COOKIE_DOMAIN
		)
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		param = urllib.parse.unquote_plus(request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE))
		return redirect(param)