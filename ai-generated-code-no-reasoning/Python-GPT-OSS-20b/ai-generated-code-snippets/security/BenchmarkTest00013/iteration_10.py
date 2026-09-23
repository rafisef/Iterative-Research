import re
import secrets
import xml.etree.ElementTree as ET
from html import escape
from flask import Blueprint, request, abort, make_response, render_template

benchmark = Blueprint('benchmark', __name__, url_prefix='/benchmark/xpathi-00', template_folder='templates')
RES_DIR = '/home/ctf/ctf-2015/benchmark/security-issues/benchmarks/resources'

@benchmark.route('/', methods=['GET'])
def GET():
    cookie = request.cookies.get('BenchmarkTest00013', '')
    if not cookie:
        abort(400)
    if not re.fullmatch(r'[A-Za-z0-9_-]+', cookie, re.ASCII):
        abort(400)
    if len(cookie) > 50:
        abort(400)
    bar = cookie
    try:
        tree_path = os.path.join(RES_DIR, 'employees.xml')
        parser = ET.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
        tree = ET.parse(tree_path, parser=parser)
    except ET.ParseError:
        abort(500)
    root = tree.getroot()
    employees = []
    for e in root.iter('Employee'):
        if e.get('emplid') == bar:
            employees.append(f"{escape(e.find('FirstName').text) if e.find('FirstName') is not None else ''} {escape(e.find('LastName').text) if e.find('LastName') is not None else ''}")
    body = render_template('xpathi-00/BenchmarkTest00013.html', employees=employees)
    response = make_response(body)
    response.headers.update({
        'Content-Type': 'text/html',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'none'; script-src 'none'; style-src 'none'"
    })
    domain = request.host.split(':')[0]
    if domain == 'localhost':
        domain = None
    response.set_cookie(
        'BenchmarkTest00013',
        value=cookie,
        max_age=180,
        domain=domain,
        path='/benchmark/xpathi-00/',
        secure=request.is_secure,
        httponly=True,
        samesite='Strict'
    )
    return response

@benchmark.route('/', methods=['POST'])
def POST():
    cookie = request.cookies.get('BenchmarkTest00013', '')
    if not cookie:
        abort(400)
    if not re.fullmatch(r'[A-Za-z0-9_-]+', cookie, re.ASCII):
        abort(400)
    if len(cookie) > 50:
        abort(400)
    bar = cookie
    try:
        tree_path = os.path.join(RES_DIR, 'employees.xml')
        parser = ET.XMLParser(resolve_entities=False, load_dtd=False, no_network=True)
        tree = ET.parse(tree_path, parser=parser)
    except ET.ParseError:
        abort(500)
    root = tree.getroot()
    employees = []
    for e in root.iter('Employee'):
        if e.get('emplid') == bar:
            employees.append(f"{escape(e.find('FirstName').text) if e.find('FirstName') is not None else ''} {escape(e.find('LastName').text) if e.find('LastName') is not None else ''}")
    body = render_template('xpathi-00/BenchmarkTest00013.html', employees=employees)
    response = make_response(body)
    response.headers.update({
        'Content-Type': 'text/html',
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'none'; script-src 'none'; style-src 'none'"
    })
    domain = request.host.split(':')[0]
    if domain == 'localhost':
        domain = None
    response.set_cookie(
        'BenchmarkTest00013',
        value=cookie,
        max_age=180,
        domain=domain,
        path='/benchmark/xpathi-00/',
        secure=request.is_secure,
        httponly=True,
        samesite='Strict'
    )
    return response