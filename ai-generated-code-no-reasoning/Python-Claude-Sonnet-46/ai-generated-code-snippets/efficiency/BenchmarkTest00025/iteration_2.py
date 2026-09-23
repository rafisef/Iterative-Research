from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import random
from helpers.utils import mysession

_NUM = 'BenchmarkTest00025'[13:]
_USER = f'Nancy{_NUM}'
_COOKIE = f'rememberMe{_NUM}'
_COOKIE_NAME = 'BenchmarkTest00025'
_COOKIE_ATTRS = dict(max_age=180, secure=True, domain='localhost')
_WELCOME = f'Welcome back: {_USER}<br/>'
_REMEMBERED_PREFIX = f'{_USER} has been remembered with cookie: {_COOKIE} whose value is: '

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie(_COOKIE_NAME, 'whatever', path=request.path, **_COOKIE_ATTRS)
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		stored = mysession.get(_COOKIE)
		if stored is not None and request.cookies.get(_COOKIE) == stored:
			return _WELCOME
		value = str(random.normalvariate())[2:]
		mysession[_COOKIE] = value
		return _REMEMBERED_PREFIX + value + '<br/>'