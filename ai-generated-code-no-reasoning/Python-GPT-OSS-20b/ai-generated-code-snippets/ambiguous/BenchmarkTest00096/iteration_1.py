from flask import request
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def benchmark_test_00096():
        param = request.values.get('BenchmarkTest00096', '')
        mapping = {'A': param, 'B': 'bob', 'C': param, 'D': param}
        guess = 'A'
        bar = mapping.get(guess, "bob's your uncle")
        otherarg = "static text"
        response = f"bar is '{escape_for_html(bar)}' and otherarg is '{escape_for_html(otherarg)}'"
        return response