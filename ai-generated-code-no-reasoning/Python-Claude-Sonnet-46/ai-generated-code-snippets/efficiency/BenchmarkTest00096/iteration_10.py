from flask import request

_ROUTE = '/benchmark/xss-00/BenchmarkTest00096'
_PARAM = 'BenchmarkTest00096'
_RESPONSE = "bar is '{}' and otherarg is 'static text'"

def init(app):

	@app.route(_ROUTE, methods=['GET', 'POST'])
	def BenchmarkTest00096():
		return _RESPONSE.format(request.form.get(_PARAM, ''))