from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import pickle
import base64
import helpers.utils

_COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
_COOKIE_MAX_AGE = 180
_DECODED_COOKIE = base64.urlsafe_b64decode(_COOKIE_VALUE)

def init(app):

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
	def BenchmarkTest00078_get():
		response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
		response.set_cookie('BenchmarkTest00078', _COOKIE_VALUE,
			max_age=_COOKIE_MAX_AGE,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
	def BenchmarkTest00078_post():
		raw = request.cookies.get("BenchmarkTest00078")
		if raw is None:
			helpers.utils.sharedstr = "no pickles to be seen here"
			return 'Unpickling failed!'

		if raw == _COOKIE_VALUE:
			decoded = _DECODED_COOKIE
		else:
			param = urllib.parse.unquote_plus(raw)
			try:
				decoded = base64.urlsafe_b64decode(param)
			except Exception:
				return 'Unpickling failed!'

		helpers.utils.sharedstr = "no pickles to be seen here"

		try:
			pickle.loads(decoded)
		except Exception:
			return 'Unpickling failed!'

		return f'shared string is {helpers.utils.sharedstr}'