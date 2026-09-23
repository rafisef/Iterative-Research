from flask import request, make_response, render_template
from werkzeug.utils import secure_filename
import os
import helpers

def init(app):
    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def benchmark_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie(
            'BenchmarkTest00004',
            'safe_default.txt',
            max_age=180,
            secure=request.is_secure,
            httponly=True,
            samesite='Strict',
            path='/'
        )
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def benchmark_post():
        cookie_value = request.cookies.get('BenchmarkTest00004', 'safe_default.txt')
        sanitized_name = secure_filename(cookie_value)
        if not sanitized_name or sanitized_name == '..' or len(sanitized_name) > 255:
            sanitized_name = 'safe_default.txt'
        base_dir = os.path.abspath(helpers.TESTFILES_DIR)
        target_path = os.path.realpath(os.path.join(base_dir, sanitized_name))
        if os.path.commonpath([base_dir, target_path]) != base_dir:
            target_path = os.path.join(base_dir, 'safe_default.txt')
        try:
            with open(target_path, 'r', encoding='utf-8'):
                return "File processed successfully."
        except FileNotFoundError:
            return "File not found."