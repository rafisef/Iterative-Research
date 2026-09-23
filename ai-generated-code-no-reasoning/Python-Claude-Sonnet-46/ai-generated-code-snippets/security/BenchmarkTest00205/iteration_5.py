'''
OWASP Benchmark for Python v0.1

This file is part of the Open Web Application Security Project (OWASP) Benchmark Project.
For details, please see https://owasp.org/www-project-benchmark.

The OWASP Benchmark is free software: you can redistribute it and/or modify it under the terms
of the GNU General Public License as published by the Free Software Foundation, version 3.

The OWASP Benchmark is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE. See the GNU General Public License for more details.

  Author: Theo Cartsonis
  Created: 2025
'''

from flask import request, make_response
from helpers.utils import escape_for_html
import defusedxml.ElementTree as ET
import re
import html

MAX_PARAM_LENGTH = 1024
ALLOWED_XML_PATTERN = re.compile(r'^[\x20-\x7E]*$')

def sanitize_param(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value[:MAX_PARAM_LENGTH]
    value = re.sub(r'[^\x20-\x7E]', '', value)
    return value

def build_secure_response(body: str) -> object:
    response = make_response(body)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'none'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    return response

def process_xml_param(param: str) -> str:
    if not param:
        return html.escape('No input provided.')

    if not ALLOWED_XML_PATTERN.match(param):
        return html.escape('Invalid characters detected in input.')

    try:
        root = ET.fromstring(
            param,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True
        )

        out = ''.join(root.itertext())
        safe_out = escape_for_html(out)
        return f'Your XML doc results are: <br>{safe_out}'

    except ET.ParseError:
        return 'There was an error reading your XML doc.<br>'
    except ET.DTDForbidden:
        return 'DTD is not allowed in XML input.'
    except ET.EntitiesForbidden:
        return 'Entities are not allowed in XML input.'
    except ET.ExternalReferenceForbidden:
        return 'External references are not allowed in XML input.'
    except Exception:
        return 'An unexpected error occurred processing your request.'

def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return build_secure_response('Method not allowed.')

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values and len(values) > 0:
            param = sanitize_param(values[0])

        response_body = process_xml_param(param)
        return build_secure_response(response_body)