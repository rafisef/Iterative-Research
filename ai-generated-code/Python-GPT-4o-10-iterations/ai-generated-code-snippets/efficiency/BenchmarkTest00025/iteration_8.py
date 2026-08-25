from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import mysession
from random import normalvariate

def init(app):
	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
	def BenchmarkTest00025():
		if request.method == 'POST':
			param = request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied")
			bar = param

			num = '00025'
			user = f'Nancy{num}'
			cookie = f'rememberMe{num}'
			value = str(normalvariate(0, 1))[2:]

			if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
				return f'Welcome back: {user}<br/>'
			else:
				mysession[cookie] = value
				return (
					f'{user} has been remembered with cookie: '
					f'{cookie} whose value is: {mysession[cookie]}<br/>'
				)

		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response