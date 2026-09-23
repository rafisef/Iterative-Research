from flask import request

_STATIC_SUFFIX = "' and otherarg is 'static text'"
_STATIC_PREFIX = "bar is '"

def init(app):

	@app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
	def BenchmarkTest00096():
		param = request.form.get("BenchmarkTest00096") or ""
		return "".join((_STATIC_PREFIX, param, _STATIC_SUFFIX))