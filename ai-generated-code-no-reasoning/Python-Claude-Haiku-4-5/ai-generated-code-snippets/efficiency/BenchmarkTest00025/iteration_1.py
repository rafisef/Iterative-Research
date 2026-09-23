from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, mysession
import urllib.parse
import random

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
		bar = param

		num = '25'
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
			RESPONSE = f'Welcome back: {user}<br/>'
		else:
			mysession[cookie] = value
			RESPONSE = f'{user} has been remembered with cookie: {cookie} whose value is: {mysession[cookie]}<br/>'

		return RESPONSE