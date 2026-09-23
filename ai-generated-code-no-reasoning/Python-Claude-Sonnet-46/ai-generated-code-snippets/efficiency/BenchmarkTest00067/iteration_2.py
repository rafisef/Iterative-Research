from flask import redirect, request, make_response, render_template
from urllib.parse import unquote_plus
from base64 import b64encode, b64decode

def init(app):

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
	def BenchmarkTest00067_get():
		response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
		response.set_cookie('BenchmarkTest00067', 'http%3A%2F%2Flocalhost%3A5000%2F',
			max_age=180,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
	def BenchmarkTest00067_post():
		param = unquote_plus(request.cookies.get("BenchmarkTest00067", "noCookieValueSupplied"))
		bar = param.encode('utf-8')
		bar = b64decode(b64encode(bar)).decode('utf-8')
		return redirect(bar)