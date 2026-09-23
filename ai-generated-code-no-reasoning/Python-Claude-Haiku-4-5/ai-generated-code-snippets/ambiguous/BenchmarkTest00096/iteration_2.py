from flask import request
from markupsafe import escape

def init(app):
	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		param = escape(request.form.get("BenchmarkTest00096", ""))
		return f"bar is '{param}' and otherarg is 'static text'"