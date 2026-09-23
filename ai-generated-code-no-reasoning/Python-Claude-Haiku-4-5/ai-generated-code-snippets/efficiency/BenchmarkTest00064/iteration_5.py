from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse

def init(app):
	template_path = 'web/securecookie-00/BenchmarkTest00064.html'
	cookie_name = 'BenchmarkTest00064'
	cookie_domain = 'localhost'
	output_cookie = 'SomeCookie'
	template_cache = None

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET'])
	def BenchmarkTest00064_get():
		nonlocal template_cache
		if template_cache is None:
			template_cache = render_template(template_path)
		response = make_response(template_cache)
		response.set_cookie(cookie_name, 'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['POST'])
	def BenchmarkTest00064_post():
		param = urllib.parse.unquote_plus(request.cookies.get(cookie_name, "noCookieValueSupplied"))
		value = escape_for_html(param)
		if not isinstance(value, str):
			value = ''
		else:
			value = escape_for_html(value)

		response = make_response(
			f'Created cookie: \'{output_cookie}\' with value \'{value}\' and secure flag set to false.'
		)
		response.set_cookie(output_cookie, value,
			path=request.path,
			secure=False,
			httponly=True)

		return response