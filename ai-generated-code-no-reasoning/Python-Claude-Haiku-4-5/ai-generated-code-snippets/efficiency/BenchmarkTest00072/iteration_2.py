from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import urllib.parse

def init(app):

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET'])
	def BenchmarkTest00072_get():
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie('BenchmarkTest00072', 'my-user-id',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['POST'])
	def BenchmarkTest00072_post():
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))

		bar = "Ifnot case passed"

		session[bar] = '12345'

		return f'Item: \'{escape_for_html(bar)}\' with value: 12345 saved in session.'