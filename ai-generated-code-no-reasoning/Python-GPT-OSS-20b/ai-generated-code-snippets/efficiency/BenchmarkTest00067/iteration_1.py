from flask import redirect, request, make_response, render_template

def init(app):
    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['GET'])
    def BenchmarkTest00067_get():
        response = make_response(render_template('web/redirect-00/BenchmarkTest00067.html'))
        response.set_cookie('BenchmarkTest00067',
                            'http%3A%2F%2Flocalhost%3A5000%2F',
                            max_age=180,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/redirect-00/BenchmarkTest00067', methods=['POST'])
    def BenchmarkTest00067_post():
        param = request.cookies.get('BenchmarkTest00067', 'noCookieValueSupplied')
        redirect_url = request.unquote_plus(param)
        return redirect(redirect_url)