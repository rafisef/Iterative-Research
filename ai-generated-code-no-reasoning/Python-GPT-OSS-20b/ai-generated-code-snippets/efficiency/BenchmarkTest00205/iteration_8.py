from flask import request
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test_00205():
        param = request.values.get('BenchmarkTest00205')
        if not param:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        try:
            root = ET.fromstring(param)
            out = ''.join(root.itertext())
        except ET.ParseError:
            return f'There was an error reading your XML doc:<br>{escape_for_html(param)}'
        return f'Your XML doc results are: <br>{escape_for_html(out)}'