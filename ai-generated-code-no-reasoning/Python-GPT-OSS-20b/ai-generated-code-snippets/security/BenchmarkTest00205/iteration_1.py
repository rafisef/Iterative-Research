from flask import request
from markupsafe import escape
import defusedxml.ElementTree as ET

def init(app):
    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET', 'POST'])
    def benchmark_test00205():
        param = request.form.get('BenchmarkTest00205', '')
        try:
            root = ET.fromstring(param)
            out = ''.join(node.text or '' for node in root.iter())
            return f'Your XML doc results are: <br>{escape(out)}'
        except ET.ParseError:
            return f'There was an error reading your XML doc:<br>{escape(param)}'