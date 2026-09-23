from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
from helpers.utils import escape_for_html

def init(app):

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00064", "noCookieValueSupplied"))
		bar = escape_for_html(param)
		value = bar if isinstance(bar, str) else ''
		response = make_response(f'Created cookie: \'SomeCookie\' with value \'{escape_for_html(value)}\' and secure flag set to false.')
		response.set_cookie('SomeCookie', value,
			path=request.path,
			secure=False,
			httponly=True)
		return response