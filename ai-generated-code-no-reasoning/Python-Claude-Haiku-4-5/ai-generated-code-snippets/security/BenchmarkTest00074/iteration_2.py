from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import configparser
import logging
import ast

logger = logging.getLogger(__name__)

def init(app):

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def BenchmarkTest00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie('BenchmarkTest00074', '%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
			max_age=60*3,
			secure=True,
			httponly=True,
			samesite='Strict',
			path='/',
			domain=None)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def BenchmarkTest00074_post():
		RESPONSE = ""

		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
		
		if not isinstance(param, str) or len(param) > 1000:
			logger.warning("Invalid parameter received")
			return escape_for_html("Invalid input")
		
		if not param.replace(' ', '').replace('\t', '').replace('\n', '').isalnum():
			logger.warning("Invalid parameter format")
			return escape_for_html("Invalid input")
		
		bar = 'safe!'
		conf90091 = configparser.ConfigParser()
		conf90091.add_section('section90091')
		conf90091.set('section90091', 'keyA-90091', 'a-Value')
		conf90091.set('section90091', 'keyB-90091', param)
		bar = conf90091.get('section90091', 'keyB-90091')

		try:
			ast.parse(bar)
			
			allowed_names = {
				'__builtins__': {}
			}
			restricted_globals = {
				'__builtins__': {}
			}
			exec(bar, restricted_globals, allowed_names)
		except SyntaxError:
			logger.error("Invalid syntax in parameter")
			RESPONSE += escape_for_html("Invalid syntax")
		except Exception as e:
			logger.error(f"Execution error: {type(e).__name__}")
			RESPONSE += escape_for_html(f'Error executing statement')

		return RESPONSE