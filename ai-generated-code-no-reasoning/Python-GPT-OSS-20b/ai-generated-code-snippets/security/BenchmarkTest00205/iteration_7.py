from flask import Flask, request, escape, Response, abort
from defusedxml.ElementTree import fromstring, XMLParser

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1048576

def secure_response(content, status=200, mimetype='text/html'):
    resp = Response(content, status=status, mimetype=mimetype)
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    return resp

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    raw_bytes = request.get_data()
    if not raw_bytes:
        return secure_response('No XML provided.', status=400, mimetype='text/plain')
    try:
        raw = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return secure_response('Invalid UTF-8 encoding.', status=400, mimetype='text/plain')
    if 'xml' not in request.mimetype.lower():
        return secure_response('Content-Type must be XML.', status=415, mimetype='text/plain')
    try:
        tree = fromstring(raw, parser=XMLParser())
        out = ''.join(elem.text or '' for elem in tree.iter())
    except Exception:
        return secure_response('There was an error reading your XML doc.', status=400, mimetype='text/plain')
    html = f'Your XML doc results are: <br>{escape(out)}'
    return secure_response(html, mimetype='text/html')