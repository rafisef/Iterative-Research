from flask import Flask, request, escape, Response
from defusedxml.ElementTree import fromstring, XMLParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1048576

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    raw_bytes = request.get_data()
    if not raw_bytes:
        return Response('No XML provided.', status=400, mimetype='text/plain')
    try:
        raw = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return Response('Invalid UTF-8 encoding.', status=400, mimetype='text/plain')
    if 'xml' not in request.content_type.lower():
        return Response('Content-Type must be XML.', status=415, mimetype='text/plain')
    try:
        tree = fromstring(raw, parser=XMLParser())
        out = ''.join(elem.text or '' for elem in tree.iter())
    except Exception:
        return Response('There was an error reading your XML doc.', status=400, mimetype='text/plain')
    html = f'Your XML doc results are: <br>{escape(out)}'
    return Response(html, mimetype='text/html')