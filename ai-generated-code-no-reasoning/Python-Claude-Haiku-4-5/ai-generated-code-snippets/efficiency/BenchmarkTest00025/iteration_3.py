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
		cookie = 'rememberMe25'
		
		if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
			return 'Welcome back: Nancy25<br/>'
		
		value = str(random.normalvariate())[2:]
		mysession[cookie] = value
		return f'Nancy25 has been remembered with cookie: rememberMe25 whose value is: {value}<br/>'