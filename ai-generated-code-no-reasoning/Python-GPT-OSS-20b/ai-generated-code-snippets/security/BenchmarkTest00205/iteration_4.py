from flask import Flask, request, escape
from defusedxml.ElementTree import fromstring

app = Flask(__name__)
MAX_XML_SIZE = 1048576
app.config['MAX_CONTENT_LENGTH'] = MAX_XML_SIZE

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    param = request.form.get('BenchmarkTest00205', '')
    if not param:
        return 'No XML provided.'
    if len(param) > MAX_XML_SIZE:
        return 'XML data too large.'
    try:
        tree = fromstring(param)
        out = ''.join([elem.text or '' for elem in tree.iter()])
    except Exception:
        return f'There was an error reading your XML doc:<br>{escape(param)}'
    return f'Your XML doc results are: <br>{escape(out)}'