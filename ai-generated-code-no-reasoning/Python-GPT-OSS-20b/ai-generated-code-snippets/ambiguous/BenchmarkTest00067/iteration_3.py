import base64
import urllib.parse
from flask import Flask, redirect, request, make_response, render_template

def init(app: Flask):
    def is_safe_url(target: str) -> bool:
        ref = urllib.parse.urlparse(request.host_url)
        test = urllib.parse.urlparse(urllib.parse.urljoin(request.host_url, target))
        return (
            test.scheme in ("http", "https")
            and ref.netloc == test.netloc
        )

    def safe_base64_decode(data: str) -> str:
        try:
            padded = data + "=" * (-len(data) % 4)
            return base64.b64decode(padded, validate=True).decode("utf-8")
        except (base64.binascii.Error, UnicodeDecodeError):
            return "/"

    @app.route("/benchmark/redirect-00/BenchmarkTest00067", methods=["GET", "POST"])
    def benchmark_test_00067():
        if request.method == "GET":
            resp = make_response(render_template("web/redirect-00/BenchmarkTest00067.html"))
            resp.set_cookie(
                "BenchmarkTest00067",
                urllib.parse.quote_plus("http://localhost:5000/"),
                max_age=180,
                secure=True,
                path="/",
                domain=request.host.split(":")[0],
                httponly=True,
                samesite="Strict",
            )
            return resp
        cookie_val = request.cookies.get("BenchmarkTest00067", "")
        decoded_url = safe_base64_decode(urllib.parse.unquote_plus(cookie_val))
        if not is_safe_url(decoded_url):
            decoded_url = "/"
        return redirect(decoded_url, code=302)