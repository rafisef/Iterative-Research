from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import helpers.utils

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET'])
    def BenchmarkTest00004_get():
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
        response.set_cookie('BenchmarkTest00004', 'Filename',
            max_age=180,
            secure=True,
            path=request.path,
            domain='localhost')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['POST'])
    def BenchmarkTest00004_post():
        bar = "This_should_always_happen"
        file_path = f'{helpers.utils.TESTFILES_DIR}/{bar}'
        try:
            with open(file_path, 'r', encoding='utf-8') as fileTarget:
                return f"Access to file: '{escape_for_html(fileTarget.name)}' created. And file already exists."
        except FileNotFoundError:
            return "File not found"