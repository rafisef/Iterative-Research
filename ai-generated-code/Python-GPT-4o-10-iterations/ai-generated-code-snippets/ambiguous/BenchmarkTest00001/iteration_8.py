from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html, TESTFILES_DIR
import os
import urllib.parse
import codecs

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET', 'POST'])
    def benchmark_test():
        if request.method == 'POST':
            return benchmark_test_post()
        return benchmark_test_get()

    def benchmark_test_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie(
            'BenchmarkTest00001', 'Filename',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost',
            httponly=True,
            samesite='Strict'
        )
        return response

    def benchmark_test_post():
        param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00001", "noCookieValueSupplied"))
        safe_param = escape_for_html(param)
        file_path = os.path.join(TESTFILES_DIR, safe_param)
        try:
            with codecs.open(file_path, 'r', 'utf-8') as file_target:
                return f"Access to file: '{escape_for_html(file_target.name)}' created. And file already exists."
        except FileNotFoundError:
            return " But file doesn't exist yet."