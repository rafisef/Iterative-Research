from flask import request
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET'])
    def BenchmarkTest00096_get():
        return BenchmarkTest00096_post()

    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['POST'])
    def BenchmarkTest00096_post():
        param = request.form.get("BenchmarkTest00096", "")
        return f"bar is '{param}' and otherarg is 'static text'"