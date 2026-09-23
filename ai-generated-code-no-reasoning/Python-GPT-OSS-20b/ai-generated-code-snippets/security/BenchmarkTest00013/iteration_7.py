import os
import re
import secrets
import urllib.parse
import xml.etree.ElementTree as ET
from html import escape
from flask import Blueprint, request, abort, make_response, render_template

benchmark = Blueprint('benchmark', __name__)

RES_DIR = '/path/to/resources'

@benchmark.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET', 'POST'])
def BenchmarkTest00013():
    if request.method == 'GET':
        token = secrets.token_urlsafe(16)
        resp = make_response(render_template('benchmark/xpathi-00/BenchmarkTest00013.html'))
        domain = request.host.split(':')[0]
        resp.set_cookie(
            'BenchmarkTest00013',
            token,
            max_age=180,
            path='/benchmark/xpathi-00/',
            domain=domain,
            secure=True,
            httponly=True,
            samesite='Strict',
        )
        resp.headers.update({
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'none'; script-src 'none'; style-src 'none'",
        })
        return resp

    raw = request.cookies.get('BenchmarkTest00013', '')
    param = urllib.parse.unquote_plus(raw)
    if not re.fullmatch(r'[A-Za-z0-9]+', param) or len(param) > 50:
        abort(400)
    bar = param or 'alsosafe'
    parser = ET.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
    try:
        tree_path = os.path.join(RES_DIR, 'employees.xml')
        root = ET.parse(tree_path, parser=parser)
        nodes = [e for e in root.iter('Employee') if e.get('emplid') == bar]
        node_strings = [escape(e.text or '') for e in nodes]
        body = f'Your XPATH query results are: <br>[ {", ".join(node_strings)} ]'
        resp = make_response(body)
        resp.headers.update({
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
            'Content-Security-Policy': "default-src 'none'; script-src 'none'; style-src 'none'",
        })
        return resp
    except Exception:
        resp = make_response('Error parsing XPath Query.')
        resp.headers.update({
            'Content-Type': 'text/plain; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'SAMEORIGIN',
            'X-XSS-Protection': '1; mode=block',
        })
        return resp