import urllib.parse
from flask import make_response, request, render_template, current_app

def init(app):
    @app.route('/benchmark/securecookie-00/BenchmarkTest00064', methods=['GET', 'POST'])
    def benchmark():
        if request.method == 'GET':
            response = make_response(render_template('web/securecookie-00/BenchmarkTest00064.html'))
            response.set_cookie(
                'BenchmarkTest00064',
                'whatever',
                max_age=180,
                secure=True,
                path=request.path,
                domain=request.host.split(':')[0],
                httponly=True,
                samesite='Lax'
            )
            return response

        raw_value = request.cookies.get('BenchmarkTest00064', '')
        decoded = urllib.parse.unquote_plus(raw_value)
        sanitized = current_app.escape_for_html(decoded)

        cookie_name = 'SomeCookie'
        response_text = (
            f"Created cookie: '{cookie_name}' with value "
            f"'{current_app.escape_for_html(sanitized)}' and secure flag set to false."
        )
        response = make_response(response_text)
        response.set_cookie(
            cookie_name,
            urllib.parse.quote_plus(sanitized),
            path=request.path,
            secure=False,
            httponly=True,
            samesite='Strict'
        )
        return response