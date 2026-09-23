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
		_set_cookie(response, 'BenchmarkTest00025', secrets.token_hex(16), request.path)
		return response

	def _set_cookie(response, name, value, path=None):
		cookie_kwargs = {
			'max_age': 180,
			'secure': True,
			'httponly': True,
			'samesite': 'Strict'
		}
		if path:
			cookie_kwargs['path'] = path
		response.set_cookie(name, value, **cookie_kwargs)

	def _handle_post():
		user = 'Nancy25'
		cookie_name = 'rememberMe25'
		cookie_value = mysession.get(cookie_name)
		request_cookie = request.cookies.get(cookie_name)
		
		if cookie_value and request_cookie == cookie_value:
			response_text = f'Welcome back: {escape_for_html(user)}<br/>'
		else:
			cookie_value = secrets.token_hex(16)
			mysession[cookie_name] = cookie_value
			response_text = f'{escape_for_html(user)} has been remembered with cookie: {escape_for_html(cookie_name)} whose value is: {escape_for_html(cookie_value)}<br/>'

		response = make_response(response_text)
		_set_cookie(response, cookie_name, cookie_value)
		return response