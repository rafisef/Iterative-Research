from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        param = request.form.get('BenchmarkTest00205', '')
        bar = param
        try:
            root = ET.fromstring(bar)
            out = ''.join(node.text or '' for node in root.iter())
            response = f'Your XML doc results are: <br>{escape_for_html(out)}'
        except ET.ParseError:
            response = f'There was an error reading your XML doc:<br>{escape_for_html(bar)}'
        return response