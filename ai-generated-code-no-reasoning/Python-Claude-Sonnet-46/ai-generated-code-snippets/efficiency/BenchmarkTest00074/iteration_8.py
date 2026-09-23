from flask import request, make_response, render_template
from helpers.utils import escape_for_html
from urllib.parse import unquote_plus

_COOKIE_NAME = 'BenchmarkTest00074'
_COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
_COOKIE_SETTINGS = {'max_age': 180, 'secure': True, 'domain': 'localhost'}
_COMPILED_CACHE = {}

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET', 'POST'])
	def BenchmarkTest00074():
		if request.method == 'GET':
			response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
			response.set_cookie(_COOKIE_NAME, _COOKIE_VALUE, path=request.path, **_COOKIE_SETTINGS)
			return response
		bar = unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))
		try:
			code = _COMPILED_CACHE.get(bar)
			if code is None:
				code = compile(bar, '<string>', 'exec')
				_COMPILED_CACHE[bar] = code
			ns = {"RESPONSE": ""}
			exec(code, ns)
		except Exception:
			return f'Error executing statement \'{escape_for_html(bar)}\''
		return ns["RESPONSE"]