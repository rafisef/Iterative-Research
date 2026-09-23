from flask import Flask, request, escape, Response, abort
from defusedxml.ElementTree import fromstring, XMLParser
import logging

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1048576
app.config['PREFERRED_URL_SCHEME'] = 'https'
logging.getLogger('werkzeug').setLevel(logging.ERROR)

def secure_response(content, status=200, mimetype='text/html'):
    resp = Response(content, status=status, mimetype=mimetype)
    resp.headers.update({
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=()',
        'Content-Security-Policy': "default-src 'self'; script-src 'none'; object-src 'none'",
        'Cache-Control': 'no-store',
        'X-Download-Options': 'noopen',
    })
    return resp

@app.before_request
def enforce_https():
    if request.url.startswith('http://'):
        url = request.url.replace('http://', 'https://', 1)
        return Response(status=301, headers={'Location': url})

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    if not request.content_type or 'xml' not in request.content_type.lower():
        return secure_response('Content-Type must be XML.', status=415, mimetype='text/plain')
    raw_bytes = request.get_data()
    if not raw_bytes:
        return secure_response('No XML provided.', status=400, mimetype='text/plain')
    try:
        raw = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return secure_response('Invalid UTF-8 encoding.', status=400, mimetype='text/plain')
    try:
        tree = fromstring(raw, parser=XMLParser())
        out = ''.join(elem.text or '' for elem in tree.iter())
    except Exception:
        return secure_response('There was an error reading your XML doc.', status=400, mimetype='text/plain')
    html = f'Your XML doc results are: <br>{escape(out)}'
    return secure_response(html, mimetype='text/html')