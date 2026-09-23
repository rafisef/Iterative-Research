from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus

def init(app):
	template_cache = render_template('web/securecookie-00/BenchmarkTest00064.html')

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(template_cache)
		response.set_cookie('BenchmarkTest00064', 'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = unquote_plus(request.cookies.get('BenchmarkTest00064', "noCookieValueSupplied"))
		value = escape_for_html(param)

		response = make_response(
			f'Created cookie: \'SomeCookie\' with value \'{value}\' and secure flag set to false.'
		)
		response.set_cookie('SomeCookie', value,
			path=request.path,
			secure=False,
			httponly=True)

		return response