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

from flask import request, make_response, abort
from helpers.utils import escape_for_html
import defusedxml.ElementTree as ET
import re
import html
import logging
import unicodedata

MAX_PARAM_LENGTH = 1024
MAX_XML_DEPTH = 10
MAX_XML_NODES = 100
ALLOWED_XML_PATTERN = re.compile(r'^[\x20-\x7E]*$')

logger = logging.getLogger(__name__)

def sanitize_param(value: str) -> str:
    if not isinstance(value, str):
        return ""
    value = value[:MAX_PARAM_LENGTH]
    value = unicodedata.normalize('NFC', value)
    value = re.sub(r'[^\x20-\x7E]', '', value)
    value = value.strip()
    return value

def validate_content_type(req) -> bool:
    content_type = req.content_type or ''
    return 'application/x-www-form-urlencoded' in content_type or 'multipart/form-data' in content_type

def check_xml_complexity(param: str) -> bool:
    depth = 0
    max_depth = 0
    node_count = 0
    for char in param:
        if char == '<':
            node_count += 1
            if node_count > MAX_XML_NODES:
                return False
        if char == '>':
            if depth > max_depth:
                max_depth = depth
            if max_depth > MAX_XML_DEPTH:
                return False
    return True

def build_secure_response(body: str, status_code: int = 200) -> object:
    response = make_response(body, status_code)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = "default-src 'none'; base-uri 'none'; form-action 'none'"
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=(), payment=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-XSS-Protection'] = '0'
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response

def process_xml_param(param: str) -> tuple:
    if not param:
        return html.escape('No input provided.'), 400

    if not ALLOWED_XML_PATTERN.match(param):
        logger.warning("Invalid characters detected in XML input.")
        return html.escape('Invalid characters detected in input.'), 400

    if not check_xml_complexity(param):
        logger.warning("XML input exceeded complexity limits.")
        return html.escape('XML input is too complex.'), 400

    if any(keyword in param.lower() for keyword in ['<!entity', '<!doctype', 'system', 'public', 'notation']):
        logger.warning("Potentially dangerous XML construct detected.")
        return html.escape('Disallowed XML construct detected.'), 400

    try:
        root = ET.fromstring(
            param,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True
        )

        text_parts = list(root.itertext())
        if len(text_parts) > MAX_XML_NODES:
            return html.escape('XML output too large.'), 400

        out = ''.join(text_parts)

        if len(out) > MAX_PARAM_LENGTH:
            out = out[:MAX_PARAM_LENGTH]

        safe_out = escape_for_html(out)
        return f'Your XML doc results are: <br>{safe_out}', 200

    except ET.ParseError:
        logger.info("XML parse error encountered.")
        return html.escape('There was an error reading your XML doc.'), 400
    except ET.DTDForbidden:
        logger.warning("DTD detected in XML input.")
        return html.escape('DTD is not allowed in XML input.'), 400
    except ET.EntitiesForbidden:
        logger.warning("Entities detected in XML input.")
        return html.escape('Entities are not allowed in XML input.'), 400
    except ET.ExternalReferenceForbidden:
        logger.warning("External reference detected in XML input.")
        return html.escape('External references are not allowed in XML input.'), 400
    except Exception:
        logger.exception("Unexpected error processing XML input.")
        return html.escape('An unexpected error occurred processing your request.'), 500

def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return build_secure_response(html.escape('Method not allowed.'), 405)

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        if not validate_content_type(request):
            return build_secure_response(html.escape('Unsupported Media Type.'), 415)

        if request.content_length is not None and request.content_length > 65536:
            return build_secure_response(html.escape('Request entity too large.'), 413)

        try:
            values = request.form.getlist("BenchmarkTest00205")
        except Exception:
            logger.warning("Failed to parse form data.")
            return build_secure_response(html.escape('Bad request.'), 400)

        param = ""
        if values:
            param = sanitize_param(values[0])

        response_body, status_code = process_xml_param(param)
        return build_secure_response(response_body, status_code)