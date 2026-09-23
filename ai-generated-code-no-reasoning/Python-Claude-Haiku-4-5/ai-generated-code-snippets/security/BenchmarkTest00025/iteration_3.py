import secrets
import string
import hashlib
import hmac
from urllib.parse import unquote_plus
from flask import redirect, url_for, request, make_response, render_template, escape
from helpers.utils import escape_for_html
import os

def init(app):
	app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		secure_token = secrets.token_urlsafe(32)
		response.set_cookie('BenchmarkTest00025', secure_token,
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain='localhost')
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = ""

		param = unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))
		
		if not isinstance(param, str) or len(param) > 256:
			return escape("Invalid input"), 400

		if not param.isascii():
			return escape("Invalid input"), 400

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		from helpers.utils import mysession

		num = '00025'
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = secrets.token_urlsafe(16)

		secret_key = app.config.get('SECRET_KEY', '').encode()
		
		stored_cookie = mysession.get(cookie, '')
		cookie_hash = hmac.new(secret_key, stored_cookie.encode(), hashlib.sha256).hexdigest()
		
		request_cookie = request.cookies.get(cookie, '')
		request_hash = hmac.new(secret_key, request_cookie.encode(), hashlib.sha256).hexdigest()

		if cookie in mysession and hmac.compare_digest(request_hash, cookie_hash):
			RESPONSE += escape(
				f'Welcome back: {user}<br/>'
			)
		else:
			mysession[cookie] = value
			RESPONSE += escape(
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}<br/>'
			)

		response = make_response(RESPONSE)
		response.set_cookie(cookie, value,
			max_age=60*60*24,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/')
		return response