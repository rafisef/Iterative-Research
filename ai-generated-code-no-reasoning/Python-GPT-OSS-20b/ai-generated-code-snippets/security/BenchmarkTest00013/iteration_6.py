import re
import urllib.parse
import secrets
import xml.etree.ElementTree as ET
from flask import (
    Blueprint, request, abort, make_response, current_app, render_template,
)

benchmark = Blueprint('benchmark', __name__)

RES_DIR = '/path/to/resources'  # Adjust as needed

@benchmark.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET', 'POST'])
def BenchmarkTest00013():
    if request.method == 'GET':
        token = secrets.token_urlsafe(16)
        response = make_response(render_template('benchmark/xpathi-00/BenchmarkTest00013.html'))
        domain = request.host.split(':')[0]
        response.set_cookie(
            'BenchmarkTest00013',
            token,
            max_age=180,
            path='/benchmark/xpathi-00/',
            domain=domain,
            secure=True,
            httponly=True,
            samesite='Strict',
        )
        return response

    if request.method == 'POST':
        raw = request.cookies.get('BenchmarkTest00013', '')
        param = urllib.parse.unquote_plus(raw)
        if not re.fullmatch(r'[A-Za-z0-9]+', param):
            abort(400)
        if len(param) > 50:
            abort(400)
        bar = param or 'alsosafe'
        parser = ET.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
        try:
            root = ET.parse(f'{RES_DIR}/employees.xml', parser=parser)
            nodes = [e for e in root.iter('Employee') if e.get('emplid') == bar]
            node_strings = [escape_for_html(e.text or '') for e in nodes]
            response_text = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
            response = make_response(response_text)
            response.headers['Content-Type'] = 'text/html; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            return response
        except Exception:
            response = make_response('Error parsing XPath Query.')
            response.headers['Content-Type'] = 'text/plain; charset=utf-8'
            response.headers['Cache-Control'] = 'no-store'
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'SAMEORIGIN'
            return response