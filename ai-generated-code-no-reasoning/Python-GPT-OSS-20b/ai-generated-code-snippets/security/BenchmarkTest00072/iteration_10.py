import os
from flask import Flask, render_template_string, request, session, make_response, escape
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField
from wtforms.validators import DataRequired, Length, Regexp

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY environment variable must be set.")

app = Flask(__name__)
app.secret_key = secret_key
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_SAMESITE="Strict",
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

CSRFProtect(app)

class BenchmarkForm(FlaskForm):
    benchmark = StringField(
        "Benchmark",
        validators=[DataRequired(), Length(max=50), Regexp(r"^[a-zA-Z0-9]*$")],
    )

@app.route("/app/BenchmarkTest00072", methods=["GET", "POST"])
def benchmark_test_00072():
    form = BenchmarkForm()
    if form.validate_on_submit():
        session["benchmark_test_00072"] = form.benchmark.data
        cookie_value = request.cookies.get("BenchmarkTest00072", "")
        bar = escape(cookie_value)
        return render_template_string("<h1>{{ bar }}</h1>", bar=bar)
    resp = make_response(
        render_template_string(
            """
            <form method="POST">
                {{ form.hidden_tag() }}
                {{ form.benchmark }}
                <input type="submit" value="Submit" />
            </form>
            """,
            form=form,
        )
    )
    resp.set_cookie(
        "BenchmarkTest00072",
        "12345",
        max_age=3600,
        path="/app/BenchmarkTest00072",
        httponly=True,
        secure=True,
        samesite="Strict",
    )
    return resp

@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';"
    )
    response.headers["X-Download-Options"] = "noopen"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-DNS-Prefetch-Control"] = "off"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, proxy-revalidate"
    response.headers["Pragma"] = "no-cache"
    return response

if __name__ == "__main__":
    app.run(ssl_context="adhoc")