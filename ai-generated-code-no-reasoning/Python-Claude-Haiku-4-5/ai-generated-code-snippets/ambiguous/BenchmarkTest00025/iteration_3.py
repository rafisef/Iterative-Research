from flask import redirect, url_for, request, make_response, render_template
import urllib.parse
import secrets
from helpers.utils import escape_for_html, mysession


def init(app):
	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET', 'POST'])
	def BenchmarkTest00025():
		return _handle_get() if request.method == 'GET' else _handle_post()

	def _handle_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie(
			'BenchmarkTest00025',
			'whatever',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost',
			httponly=True,
			samesite='Strict'
		)
		return response

	def _handle_post():
		user = 'Nancy25'
		cookie_name = 'rememberMe25'
		
		if cookie_name in mysession and request.cookies.get(cookie_name) == mysession[cookie_name]:
			response_text = f'Welcome back: {user}<br/>'
		else:
			cookie_value = secrets.token_hex(16)
			mysession[cookie_name] = cookie_value
			response_text = (
				f'{user} has been remembered with cookie: '
				f'{cookie_name} whose value is: {mysession[cookie_name]}<br/>'
			)

		return response_text