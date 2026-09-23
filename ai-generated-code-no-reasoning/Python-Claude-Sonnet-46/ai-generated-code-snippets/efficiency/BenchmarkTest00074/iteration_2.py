from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import configparser

_COOKIE_NAME = 'BenchmarkTest00074'
_COOKIE_VALUE = '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27'
_SECTION = 'section90091'
_KEY = 'keyB-90091'

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie(_COOKIE_NAME, _COOKIE_VALUE,
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get(_COOKIE_NAME, "noCookieValueSupplied"))

		conf = configparser.RawConfigParser()
		conf.read_dict({_SECTION: {'keyA-90091': 'a-Value', _KEY: param}})
		bar = conf.get(_SECTION, _KEY)

		try:
			exec(bar)
		except Exception:
			RESPONSE = f'Error executing statement \'{escape_for_html(bar)}\''

		return RESPONSE