from flask import Blueprint, request, current_app
import logging
from helpers.utils import escape_for_html

benchmark_bp = Blueprint("benchmark", __name__)

@benchmark_bp.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

@benchmark_bp.route("/benchmark/xss-00/BenchmarkTest00096", methods=["GET", "POST"])
def benchmark_test_00096() -> str:
    logging.info("benchmark_test_00096 called")
    user_value = request.values.get("BenchmarkTest00096", "")
    return _format_response(user_value)

def _format_response(user_value: str) -> str:
    return f"bar is '{escape_for_html(user_value)}' and otherarg is '{_get_static_text()}'"

def _get_static_text() -> str:
    return current_app.config.get("STATIC_TEXT", "static text")

@benchmark_bp.route("/health")
def health() -> tuple[str, int]:
    return "OK", 200

def init(app) -> None:
    app.register_blueprint(benchmark_bp)
    app.config.setdefault("STATIC_TEXT", "static text")