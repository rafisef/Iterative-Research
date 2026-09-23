from flask import request
from helpers.utils import escape_for_html

STATIC_TEXT = "static text"

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def benchmark_test_00096() -> str:
        user_value = request.values.get('BenchmarkTest00096', '')
        return format_response(user_value)

def format_response(user_value: str) -> str:
    return f"bar is '{escape_for_html(user_value)}' and otherarg is '{STATIC_TEXT}'"