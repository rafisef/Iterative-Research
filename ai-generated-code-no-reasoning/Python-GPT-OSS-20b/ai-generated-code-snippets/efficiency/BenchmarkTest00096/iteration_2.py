from flask import request
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def BenchmarkTest00096():
        param = request.values.get("BenchmarkTest00096", "")
        return f"bar is '{param}' and otherarg is 'static text'"