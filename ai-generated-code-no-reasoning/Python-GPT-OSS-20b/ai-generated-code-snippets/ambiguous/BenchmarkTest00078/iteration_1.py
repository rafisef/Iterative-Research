from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html

def init(app):
    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['GET'])
    def BenchmarkTest00078_get():
        response = make_response(render_template('web/deserialization-00/BenchmarkTest00078.html'))
        response.set_cookie(
            'BenchmarkTest00078',
            'gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-UjAFilEtjdWIu',
            max_age=60 * 3,
            secure=True,
            path=request.path,
            domain='localhost',
        )
        return response

    @app.route('/benchmark/deserialization-00/BenchmarkTest00078', methods=['POST'])
    def BenchmarkTest00078_post():
        RESPONSE = ""
        param = request.cookies.get("BenchmarkTest00078", "noCookieValueSupplied")
        string9895 = f"help{param}snapes on a plane"
        bar = string9895[4:-17]
        import pickle, base64, helpers.utils
        helpers.utils.sharedstr = "no pickles to be seen here"
        try:
            unpickled = pickle.loads(base64.urlsafe_b64decode(bar))
        except Exception:
            return "Unpickling failed!"
        RESPONSE += f"shared string is {helpers.utils.sharedstr}"
        return RESPONSE