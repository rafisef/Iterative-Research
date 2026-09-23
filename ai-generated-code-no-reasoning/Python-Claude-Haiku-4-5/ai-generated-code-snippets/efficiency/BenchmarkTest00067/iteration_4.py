from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import base64
import flask

def init(app):
	_template_cache = render_template('web/redirect-00/BenchmarkTest00067.html')
	_cookie_value = 'http%3A%2F%2Flocalhost%3A5000%2F'
	_cookie_params = {
		'max_age': 180,
		'secure': True,
		'path': '/benchmark/redirect-00/BenchmarkTest00067',
		'domain': 'localhost'
	}
	_default_param = "noCookieValueSupplied"

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET', 'POST'])
	def BenchmarkTest00067():
		if request.method == 'GET':
			response = make_response(_template_cache)
			response.set_cookie('BenchmarkTest00067', _cookie_value, **_cookie_params)
			return response
		else:
			param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00067", _default_param))
			return redirect(param)