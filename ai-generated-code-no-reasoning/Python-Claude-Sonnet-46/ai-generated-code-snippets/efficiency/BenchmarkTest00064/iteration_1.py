from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import io
import helpers.utils
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

		value = bar.encode('utf-8').decode('utf-8') if isinstance(bar, str) else bar.read(1000).decode('utf-8') if isinstance(bar, io.IOBase) else ''

		cookie = 'SomeCookie'
		response_text = f'Created cookie: \'{cookie}\' with value \'{escape_for_html(value)}\' and secure flag set to false.'

		RESPONSE = make_response(response_text)
		RESPONSE.set_cookie(cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return RESPONSE