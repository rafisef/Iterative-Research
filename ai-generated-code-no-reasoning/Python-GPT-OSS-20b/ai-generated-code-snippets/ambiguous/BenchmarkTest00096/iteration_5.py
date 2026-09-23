from flask import request
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def benchmark_test_00096() -> str:
        value = request.values.get('BenchmarkTest00096', '')
        static = "static text"
        return f"bar is '{escape_for_html(value)}' and otherarg is '{static}'"