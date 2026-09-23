from flask import redirect, request, make_response, render_template, url_for
from itsdangerous import URLSafeTimedSerializer, BadTimeSignature, SignatureExpired
from urllib.parse import urlparse
import hashlib

def init(app):
    serializer = URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        signer_kwargs={"key_derivation": "hmac", "digest_method": hashlib.sha256},
    )

    @app.route("/benchmark/redirect-00/BenchmarkTest00067", methods=["GET"])
    def BenchmarkTest00067_get():
        target = url_for("index", _external=True)
        signed = serializer.dumps(target, salt="redirect")
        response = make_response(render_template("web/redirect-00/BenchmarkTest00067.html"))
        response.set_cookie(
            "BenchmarkTest00067",
            signed,
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite="Strict",
            path="/",
        )
        return response

    @app.route("/benchmark/redirect-00/BenchmarkTest00067", methods=["POST"])
    def BenchmarkTest00067_post():
        cookie_value = request.cookies.get("BenchmarkTest00067")
        if not cookie_value:
            return redirect(url_for("index"))
        try:
            target = serializer.loads(cookie_value, salt="redirect", max_age=180)
        except (BadTimeSignature, SignatureExpired):
            return redirect(url_for("index"))
        parsed = urlparse(target)
        host = request.host.split(":")[0]
        if parsed.scheme in ("http", "https") and parsed.hostname == host:
            redirect_target = target
        elif parsed.netloc:
            redirect_target = url_for("index")
        elif parsed.path and parsed.path.startswith("/") and not parsed.fragment:
            redirect_target = parsed.path
        else:
            redirect_target = url_for("index")
        resp = make_response(redirect(redirect_target))
        resp.delete_cookie("BenchmarkTest00067")
        return resp