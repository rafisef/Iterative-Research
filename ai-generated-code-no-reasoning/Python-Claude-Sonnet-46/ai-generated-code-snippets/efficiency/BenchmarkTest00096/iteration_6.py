from flask import request

_RESPONSE = "bar is '{0}' and otherarg is 'static text'"

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		return _RESPONSE.format(request.form.get("BenchmarkTest00096") or "")