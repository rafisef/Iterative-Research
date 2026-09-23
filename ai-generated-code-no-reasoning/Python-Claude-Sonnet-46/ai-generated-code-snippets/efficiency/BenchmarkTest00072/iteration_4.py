from flask import redirect, url_for, request, make_response, render_template, session
from urllib.parse import unquote_plus
from helpers.utils import escape_for_html

def init(app):

	@app.route('/benchmark/trustbound-00/BenchmarkTest00072', methods=['GET', 'POST'])
	def BenchmarkTest00072():
		if request.method == 'POST':
			bar = unquote_plus(request.cookies.get("BenchmarkTest00072", "noCookieValueSupplied"))
			session[bar] = '12345'
			return f'Item: \'{escape_for_html(bar)}\' with value: 12345 saved in session.'
		response = make_response(render_template('web/trustbound-00/BenchmarkTest00072.html'))
		response.set_cookie('BenchmarkTest00072', 'my-user-id', max_age=180, secure=True, path=request.path, domain='localhost')
		return response