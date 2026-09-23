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

from flask import request, make_response, render_template
from helpers.utils import escape_for_html
import re
import urllib.parse
import elementpath
import xml.etree.ElementTree as ET
import helpers.utils
import secrets
import logging
import os
import hashlib
import hmac

logger = logging.getLogger(__name__)

SAFE_COOKIE_NAME = "BenchmarkTest00013"
ALLOWED_INPUT_PATTERN = re.compile(r'^[a-zA-Z0-9]{1,32}$')
_COOKIE_HMAC_KEY = secrets.token_bytes(32)
_MAX_COOKIE_LENGTH = 200
_COOKIE_MAX_AGE = 60 * 3


def _sign_cookie_value(value: str) -> str:
    sig = hmac.new(_COOKIE_HMAC_KEY, value.encode('utf-8'), hashlib.sha256).hexdigest()
    return f"{value}|{sig}"


def _verify_cookie_value(signed_value: str):
    if not isinstance(signed_value, str):
        return None
    if '|' not in signed_value:
        return None
    value, sig = signed_value.rsplit('|', 1)
    if not ALLOWED_INPUT_PATTERN.match(value):
        return None
    expected_sig = hmac.new(_COOKIE_HMAC_KEY, value.encode('utf-8'), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    return value


def _safe_xml_path() -> str:
    base = os.path.realpath(helpers.utils.RES_DIR)
    target = os.path.realpath(os.path.join(base, 'employees.xml'))
    if not target.startswith(base + os.sep):
        raise ValueError("Path traversal detected")
    if not os.path.isfile(target):
        raise ValueError("XML resource not found")
    return target


def _build_safe_bar(param: str) -> str:
    if not param or not ALLOWED_INPUT_PATTERN.match(param):
        return "alsosafe"
    lst = ['safe', param, 'moresafe']
    lst.pop(0)
    return lst[1]


def _parse_xml_safely(xml_path: str) -> ET.ElementTree:
    parser = ET.XMLParser()
    tree = ET.parse(xml_path, parser=parser)
    return tree


def init(app):

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['GET'])
    def BenchmarkTest00013_get():
        response = make_response(render_template('web/xpathi-00/BenchmarkTest00013.html'))
        raw_value = secrets.token_hex(4)
        signed_value = _sign_cookie_value(raw_value)
        response.set_cookie(
            SAFE_COOKIE_NAME,
            signed_value,
            max_age=_COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path=request.path,
            domain='localhost'
        )
        return response

    @app.route('/benchmark/xpathi-00/BenchmarkTest00013', methods=['POST'])
    def BenchmarkTest00013_post():
        RESPONSE = ""

        raw_cookie = request.cookies.get(SAFE_COOKIE_NAME, "")
        if not raw_cookie:
            return escape_for_html("No valid session cookie supplied."), 400

        try:
            decoded_cookie = urllib.parse.unquote_plus(raw_cookie)
        except Exception:
            logger.warning("Cookie decoding failed in BenchmarkTest00013")
            return escape_for_html("Invalid or tampered cookie."), 400

        if len(decoded_cookie) > _MAX_COOKIE_LENGTH:
            logger.warning("Oversized cookie value in BenchmarkTest00013")
            return escape_for_html("Invalid or tampered cookie."), 400

        param = _verify_cookie_value(decoded_cookie)
        if param is None:
            logger.warning("Cookie HMAC verification failed in BenchmarkTest00013")
            return escape_for_html("Invalid or tampered cookie."), 400

        if not ALLOWED_INPUT_PATTERN.match(param):
            logger.warning("Cookie value failed pattern check in BenchmarkTest00013")
            return escape_for_html("Invalid input."), 400

        bar = _build_safe_bar(param)

        if not ALLOWED_INPUT_PATTERN.match(bar):
            logger.warning("Input validation failed in BenchmarkTest00013: pattern mismatch")
            return escape_for_html("Invalid input."), 400

        try:
            xml_path = _safe_xml_path()
            root = _parse_xml_safely(xml_path)

            nodes = elementpath.select(
                root,
                "/Employees/Employee[@emplid=$emplid]",
                variables={"emplid": bar}
            )

            node_strings = []
            for node in nodes:
                texts = [escape_for_html(e.text) for e in node if e.text is not None]
                node_strings.append(' '.join(texts))

            safe_result = escape_for_html(", ".join(node_strings))
            RESPONSE += f'Your XPATH query results are: <br>[ {safe_result} ]'

        except ET.ParseError:
            logger.error("XML parse error in BenchmarkTest00013")
            RESPONSE += escape_for_html('Error parsing XML resource.')
        except ValueError as e:
            logger.error("Path validation error in BenchmarkTest00013: %s", e)
            RESPONSE += escape_for_html('An unexpected error occurred.')
        except Exception:
            logger.exception("Unexpected error in BenchmarkTest00013")
            RESPONSE += escape_for_html('An unexpected error occurred.')

        return RESPONSE