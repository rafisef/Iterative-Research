import base64
import urllib.parse
from flask import Flask, redirect, request, make_response, render_template

def _is_safe_url(target: str) -> bool:
    base = urllib.parse.urlparse(request.host_url)
    target = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
    return target.scheme in {"http", "https"} and base.netloc == target.netloc

def _safe_base64_decode(data: str) -> str:
    try:
        padded = data + "=" * (-len(data) % 4)
        return base64.b64decode(padded, validate=True).decode("utf-8")
    except (base64.binascii.Error, UnicodeDecodeError):
        return "/"

def init(app: Flask) -> None:
    @app.route("/benchmark/redirect-00/BenchmarkTest00067", methods=["GET", "POST"])
    def benchmark_test_00067():
        if request.method == "GET":
            resp = make_response(render_template("web/redirect-00/BenchmarkTest00067.html"))
            cookie = urllib.parse.quote_plus("http://localhost:5000/")
            resp.set_cookie(
                "BenchmarkTest00067",
                cookie,
                max_age=180,
                secure=True,
                path="/",
                domain=request.host.split(":")[0],
                httponly=True,
                samesite="Strict",
            )
            return resp
        raw = request.cookies.get("BenchmarkTest00067", "")
        url = _safe_base64_decode(urllib.parse.unquote_plus(raw))
        return redirect(url if _is_safe_url(url) else "/")