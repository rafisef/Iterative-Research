from flask import Flask, request, escape
from defusedxml.ElementTree import fromstring, XMLParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1048576

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    raw = request.get_data(as_text=True, charset='utf-8')
    if not raw:
        return 'No XML provided.'
    try:
        tree = fromstring(raw, parser=XMLParser())
        out = ''.join(elem.text or '' for elem in tree.iter())
    except Exception:
        return 'There was an error reading your XML doc.'
    return f'Your XML doc results are: <br>{escape(out)}'