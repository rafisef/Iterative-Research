from flask import request

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		param = request.form.get("BenchmarkTest00096") or ""
		return f"bar is '{param}' and otherarg is 'static text'"