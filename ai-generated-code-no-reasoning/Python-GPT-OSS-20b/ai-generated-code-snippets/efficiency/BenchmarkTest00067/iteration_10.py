from flask import Flask, request, redirect, Response

app = Flask(__name__)
COOKIE_NAME = "last_url"
COOKIE_MAX_AGE = 86400
HTML_FORM = "<html><body><form method='post'><input name='url' placeholder='URL'><button>Go</button></form></body></html>"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        return redirect(request.cookies.get(COOKIE_NAME, "/"))
    r = Response(HTML_FORM)
    r.set_cookie(COOKIE_NAME, request.path, max_age=COOKIE_MAX_AGE, secure=True, httponly=True, samesite="Lax")
    return r

if __name__ == "__main__":
    app.run(debug=True)