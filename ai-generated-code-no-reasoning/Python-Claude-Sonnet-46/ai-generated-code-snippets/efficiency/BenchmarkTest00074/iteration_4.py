from flask import request, make_response, render_template
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus

_COOKIE_NAME = 'BenchmarkTest00074'
_COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
_COOKIE_SETTINGS = {'max_age': 180, 'secure': True, 'domain': 'localhost'}

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie(_COOKIE_NAME, _COOKIE_VALUE, path=request.path, **_COOKIE_SETTINGS)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""
		bar = unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
		try:
			exec(bar)
		except Exception:
			RESPONSE = f'Error executing statement \'{escape_for_html(bar)}\''
		return RESPONSE