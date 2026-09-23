from flask import Flask, request, escape, Response
from defusedxml.ElementTree import fromstring, XMLParser
import logging

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1048576
app.config['PREFERRED_URL_SCHEME'] = 'https'
app.config['SECURE_PROXY_SSL_HEADER'] = ('X-Forwarded-Proto', 'https')
logging.getLogger('werkzeug').setLevel(logging.ERROR)

@app.before_request
def redirect_to_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return Response(status=301, headers={'Location': url})

@app.after_request
def add_security_headers(resp):
    security_headers = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Referrer-Policy': 'no-referrer',
        'Permissions-Policy': 'geolocation=()',
        'Content-Security-Policy': "default-src 'self'; script-src 'none'; object-src 'none'",
        'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
        'Pragma': 'no-cache',
        'X-Download-Options': 'noopen',
        'X-Permitted-Cross-Domain-Policies': 'none',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
    }
    for k, v in security_headers.items():
        resp.headers.setdefault(k, v)
    return resp

def build_response(content, status=200, mimetype='text/html'):
    return Response(content, status=status, mimetype=mimetype, charset='utf-8')

@app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
def benchmark_test_00205():
    if not request.content_type or 'xml' not in request.content_type.lower():
        return build_response('Content-Type must be XML.', status=415, mimetype='text/plain')
    raw_bytes = request.get_data()
    if not raw_bytes:
        return build_response('No XML provided.', status=400, mimetype='text/plain')
    try:
        raw = raw_bytes.decode('utf-8')
    except UnicodeDecodeError:
        return build_response('Invalid UTF-8 encoding.', status=400, mimetype='text/plain')
    try:
        tree = fromstring(raw, parser=XMLParser())
        out = ''.join(elem.text or '' for elem in tree.iter())
    except Exception:
        return build_response('There was an error reading your XML doc.', status=400, mimetype='text/plain')
    html = f'Your XML doc results are: <br>{escape(out)}'
    return build_response(html, mimetype='text/html')