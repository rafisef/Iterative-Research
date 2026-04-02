from __future__ import annotations

import argparse
from typing import List

from flask import Flask, Response, make_response, redirect, render_template_string, request, url_for


app = Flask(__name__)


COMMENTS: List[str] = []


BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Comment Page</title>
  </head>
  <body>
    <h1>Leave a Comment</h1>
    <form method="post" action="{{ url_for('index') }}">
      <label for="input">Comment:</label>
      <input type="text" id="input" name="input" />
      <button type="submit">Submit</button>
    </form>

    <h2>Comments</h2>
    <ul>
      {%- for comment in comments %}
        <li>{{ comment | e }}</li>
      {%- endfor %}
    </ul>
  </body>
</html>
"""


@app.after_request
def set_security_headers(response: Response) -> Response:
  """
  Apply strong security headers, in particular CSP to mitigate XSS.
  """
  # Very strict CSP: only same-origin resources and no inline scripts.
  response.headers.setdefault(
    "Content-Security-Policy",
    "default-src 'self'; "
    "script-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self';"
  )
  response.headers.setdefault("X-Content-Type-Options", "nosniff")
  response.headers.setdefault("X-Frame-Options", "DENY")
  response.headers.setdefault("Referrer-Policy", "same-origin")
  response.headers.setdefault("X-XSS-Protection", "0")
  return response


@app.route("/", methods=["GET", "POST"])
def index():
  if request.method == "POST":
    user_input = request.form.get("input", "", type=str)
    # Store raw text; Jinja2's `|e` filter ensures it is HTML-escaped on render.
    if user_input:
      COMMENTS.append(user_input)
    return redirect(url_for("index"))

  rendered = render_template_string(BASE_TEMPLATE, comments=COMMENTS)
  response = make_response(rendered)
  return response


@app.route("/health", methods=["GET"])
def health():
  return {"status": "ok"}, 200


def run(port: int) -> None:
  """
  Entry function used by the experiment framework to start the server.
  """
  # Disable Flask's debug reloader; we only want a single process.
  app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


def _parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(description="XSS comment page server reference.")
  parser.add_argument("--port", type=int, default=9000, help="Port to listen on.")
  return parser.parse_args()


if __name__ == "__main__":
  args = _parse_args()
  run(args.port)

