from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import random
from helpers.utils import mysession

_NUM = 'BenchmarkTest00025'[13:]
_USER = f'Nancy{_NUM}'
_COOKIE = f'rememberMe{_NUM}'

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[5:len(superstring)-5]

		value = str(random.normalvariate())[2:]

		if _COOKIE in mysession and request.cookies.get(_COOKIE) == mysession[_COOKIE]:
			return f'Welcome back: {_USER}<br/>'
		else:
			mysession[_COOKIE] = value
			return (
				f'{_USER} has been remembered with cookie: '
				f'{_COOKIE} whose value is: {mysession[_COOKIE]}<br/>'
			)