from flask import Blueprint, request
from helpers.utils import escape_for_html

STATIC_TEXT = "static text"

benchmark_bp = Blueprint("benchmark", __name__)

@benchmark_bp.route("/benchmark/xss-00/BenchmarkTest00096", methods=["GET", "POST"])
def benchmark_test_00096() -> str:
    user_value = request.values.get("BenchmarkTest00096", "")
    return _format_response(user_value)

def _format_response(user_value: str) -> str:
    return f"bar is '{escape_for_html(user_value)}' and otherarg is '{STATIC_TEXT}'"

def init(app):
    app.register_blueprint(benchmark_bp)