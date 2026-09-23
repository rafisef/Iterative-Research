from flask import Flask, request, Response, redirect

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        html = ("<html><body>"
                "<form method='post'>"
                "<input type='text' name='url' placeholder='URL'>"
                "<button type='submit'>Go</button>"
                "</form>"
                "</body></html>")
        resp = Response(html)
        resp.set_cookie("last_url", request.url, max_age=86400,
                        secure=True, httponly=True, samesite="Lax")
        return resp
    return redirect(request.cookies.get("last_url", "/"))