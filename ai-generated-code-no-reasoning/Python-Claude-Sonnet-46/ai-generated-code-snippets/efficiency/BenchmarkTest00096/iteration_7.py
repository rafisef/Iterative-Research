from flask import request

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		return "bar is '{0}' and otherarg is 'static text'".format(request.form.get("BenchmarkTest00096") or "")