from flask import request
from helpers.utils import escape_for_html

def init(app):
	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		param = request.form.get("BenchmarkTest00096", "")
		
		bar = param
		otherarg = "static text"
		
		response = f"bar is '{bar}' and otherarg is '{otherarg}'"
		return response