from flask import Flask, request, redirect, make_response

app = Flask(__name__)
COOKIE_NAME = "last_url"
COOKIE_MAX_AGE = 86400
HTML_FORM = "<html><body><form method='post'><input type='text' name='url' placeholder='URL'><button type='submit'>Go</button></form></body></html>"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        resp = make_response(HTML_FORM)
        resp.set_cookie(COOKIE_NAME, request.path, max_age=COOKIE_MAX_AGE, secure=True, httponly=True, samesite="Lax")
        return resp
    return redirect(request.cookies.get(COOKIE_NAME, "/"))