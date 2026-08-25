from flask import Flask, redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Required for session management

def init(app):

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['GET'])
    def BenchmarkTest00001_get():
        session['BenchmarkTest00001'] = 'Filename'
        response = make_response(render_template('web/pathtraver-00/BenchmarkTest00001.html'))
        response.set_cookie('BenchmarkTest00001', 'Filename',
                            max_age=60*3,
                            secure=True,
                            path=request.path,
                            domain='localhost')
        return response

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00001', methods=['POST'])
    def BenchmarkTest00001_post():
        RESPONSE = ""

        import urllib.parse
        param = urllib.parse.unquote_plus(session.get('BenchmarkTest00001', "noSessionValueSupplied"))

        bar = param

        import codecs
        import helpers.utils

        try:
            fileTarget = codecs.open(f'{helpers.utils.TESTFILES_DIR}/{bar}', 'r', 'utf-8')

            RESPONSE += (
                f"Access to file: \'{escape_for_html(fileTarget.name)}\' created."
            )

            RESPONSE += (
                " And file already exists."
            )

        except FileNotFoundError:
            RESPONSE += (
                " But file doesn't exist yet."
            )

        return RESPONSE

# Assuming the app initialization and configuration is handled elsewhere

if __name__ == "__main__":
    app.config['SESSION_TYPE'] = 'filesystem'
    from flask_session import Session
    Session(app)
    app.run()