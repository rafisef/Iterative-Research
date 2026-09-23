from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import pickle
import base64
import helpers.utils

_COOKIE_VALUE = 'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu'
_COOKIE_MAX_AGE = 180
_DECODED_COOKIE = base64.urlsafe_b64decode(_COOKIE_VALUE)
_UNPICKLING_FAILED = 'Unpickling failed!'
_SHARED_STRING_RESPONSE = 'shared string is '
_NO_PICKLES = "no pickles to be seen here"

def init(app):

	@app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET', 'POST'])
	def BenchmarkTest00078():
		if request.method == 'GET':
			response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
			response.set_cookie('BenchmarkTest00078', _COOKIE_VALUE,
				max_age=_COOKIE_MAX_AGE,
				secure=True,
				path=request.path,
				domain='localhost')
			return response

		raw = request.cookies.get("BenchmarkTest00078")
		if raw is None:
			helpers.utils.sharedstr = _NO_PICKLES
			return _UNPICKLING_FAILED

		if raw == _COOKIE_VALUE:
			decoded = _DECODED_COOKIE
		else:
			try:
				decoded = base64.urlsafe_b64decode(urllib.parse.unquote_plus(raw))
			except Exception:
				return _UNPICKLING_FAILED

		helpers.utils.sharedstr = _NO_PICKLES

		try:
			pickle.loads(decoded)
		except Exception:
			return _UNPICKLING_FAILED

		return _SHARED_STRING_RESPONSE + helpers.utils.sharedstr