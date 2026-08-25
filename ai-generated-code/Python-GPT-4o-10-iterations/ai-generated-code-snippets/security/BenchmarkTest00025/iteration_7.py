from flask import redirect, url_for, request, make_response, render_template, abort, jsonify
from helpers.utils import escape_for_html
import secrets

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		RESPONSE = {}

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		# Validate input to prevent any potential injection attacks
		if not param.isalnum():
			abort(400)

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		from helpers.utils import mysession

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = secrets.token_urlsafe()

		if cookie in mysession and secrets.compare_digest(request.cookies.get(cookie, ''), mysession[cookie]):
			RESPONSE['message'] = f'Welcome back: {user}'
		else:
			mysession[cookie] = value
			RESPONSE['message'] = (
				f'{user} has been remembered with cookie: '
				f'{cookie} whose value is: {mysession[cookie]}'
			)

		return jsonify(RESPONSE)