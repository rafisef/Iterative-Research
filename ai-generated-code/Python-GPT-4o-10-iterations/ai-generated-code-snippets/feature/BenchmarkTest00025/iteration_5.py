import os
import threading
import asyncio
from flask import Flask, redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

# Thread-safe dictionary for session management
session_lock = threading.Lock()
mysession = {}

app = Flask(__name__)

def init(app):

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['GET'])
	def BenchmarkTest00025_get():
		cookie_domain = os.getenv('COOKIE_DOMAIN', 'localhost')
		response = make_response(render_template('web/weakrand-00/BenchmarkTest00025.html'))
		response.set_cookie('BenchmarkTest00025', 'whatever',
			max_age=int(os.getenv('COOKIE_MAX_AGE', 60*3)),
			secure=bool(os.getenv('COOKIE_SECURE', True)),
			path=request.path,
			domain=cookie_domain)
		return response

	@app.route('/benchmark/weakrand-00/BenchmarkTest00025', methods=['POST'])
	def BenchmarkTest00025_post():
		return asyncio.run(handle_post_request())

	async def handle_post_request():
		RESPONSE = ""

		import urllib.parse
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00025", "noCookieValueSupplied"))

		superstring = f'90583{param}abcd'
		bar = superstring[len('90583'):len(superstring)-5]

		import random

		num = 'BenchmarkTest00025'[13:]
		user = f'Nancy{num}'
		cookie = f'rememberMe{num}'
		value = str(random.normalvariate())[2:]

		async with session_lock:
			if cookie in mysession and request.cookies.get(cookie) == mysession[cookie]:
				RESPONSE += (
					f'Welcome back: {user}<br/>'
				)
			else:
				mysession[cookie] = value
				RESPONSE += (
					f'{user} has been remembered with cookie: '
					f'{cookie} whose value is: {mysession[cookie]}<br/>'
				)

		return RESPONSE

init(app)