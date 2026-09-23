import urllib.parse
import configparser
from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):
	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['GET'])
	def benchmark_test_00074_get():
		response = make_response(render_template('web/codeinj-00/BenchmarkTest00074.html'))
		response.set_cookie(
			'BenchmarkTest00074',
			'%27RESPONSE+%2B%3D+%5C%27ECHOOO%5C%27%27',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost',
			httponly=True,
			samesite='Strict'
		)
		return response

	@app.route('/benchmark/codeinj-00/BenchmarkTest00074', methods=['POST'])
	def benchmark_test_00074_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00074", "noCookieValueSupplied"))
		
		config = configparser.ConfigParser()
		config.add_section('section90091')
		config.set('section90091', 'keyA-90091', 'a-Value')
		config.set('section90091', 'keyB-90091', param)
		bar = config.get('section90091', 'keyB-90091')

		try:
			exec(bar)
			response = "Code executed successfully"
		except Exception as e:
			response = f'Error executing statement \'{escape_for_html(bar)}\': {escape_for_html(str(e))}'

		return response