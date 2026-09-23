from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus

def init(app):
	template_path = 'web/securecookie-00/BenchmarkTest00064.html'
	cookie_name = 'BenchmarkTest00064'
	cookie_domain = 'localhost'
	output_cookie = 'SomeCookie'
	template_cache = render_template(template_path)
	request_path = request.path

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		response = make_response(template_cache)
		response.set_cookie(cookie_name, 'whatever',
			max_age=180,
			secure=True,
			path=request_path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))
		value = escape_for_html(param)

		response = make_response(
			f'Created cookie: \'{output_cookie}\' with value \'{value}\' and secure flag set to false.'
		)
		response.set_cookie(output_cookie, value,
			path=request_path,
			secure=False,
			httponly=True)

		return response