from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import xml.etree.ElementTree as ET
from defusedxml import ElementTree as DefusedET
import configparser
import logging
import re
import hashlib
import secrets
from markupsafe import Markup
import time
from collections import defaultdict
from functools import wraps

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
}

ERROR_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload'
}

MAX_INPUT_SIZE = 5000
MAX_OUTPUT_SIZE = 50000
MAX_DEPTH = 50
MAX_ELEMENTS = 500
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 10

request_history = defaultdict(list)

def check_rate_limit(client_id):
    if not isinstance(client_id, str) or len(client_id) > 100:
        return False
    
    current_time = time.time()
    request_history[client_id] = [
        ts for ts in request_history[client_id] 
        if current_time - ts < RATE_LIMIT_WINDOW
    ]
    
    if len(request_history[client_id]) >= MAX_REQUESTS_PER_WINDOW:
        return False
    
    request_history[client_id].append(current_time)
    return True

def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        client_id = request.remote_addr
        
        if not client_id or not isinstance(client_id, str):
            return "Invalid request", 400, ERROR_HEADERS
        
        if not check_rate_limit(client_id):
            return "Rate limit exceeded", 429, ERROR_HEADERS

        RESPONSE = ""

        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values:
            param = values[0]

        if not isinstance(param, str) or len(param) > MAX_INPUT_SIZE:
            RESPONSE += "Invalid input"
            return RESPONSE, 400, ERROR_HEADERS

        if not re.match(r'^[a-zA-Z0-9<>/=\s\-._:]*$', param):
            RESPONSE += "Invalid characters in input"
            return RESPONSE, 400, ERROR_HEADERS

        try:
            param_bytes = param.encode('utf-8')
            if len(param_bytes) > MAX_INPUT_SIZE:
                RESPONSE += "Input too large"
                return RESPONSE, 400, ERROR_HEADERS
        except (UnicodeEncodeError, AttributeError):
            RESPONSE += "Invalid encoding"
            return RESPONSE, 400, ERROR_HEADERS

        bar = 'safe!'
        conf60568 = configparser.ConfigParser()
        conf60568.add_section('section60568')
        conf60568.set('section60568', 'keyA-60568', 'a-Value')
        conf60568.set('section60568', 'keyB-60568', param)
        bar = conf60568.get('section60568', 'keyB-60568')

        try:
            doc = DefusedET.fromstring(
                bar,
                forbid_dtd=True,
                forbid_entities=True,
                forbid_external=True
            )

            out = ''
            processing = [doc]
            current_depth = 0
            element_count = 0
            
            while processing and current_depth < MAX_DEPTH and element_count < MAX_ELEMENTS:
                e = processing.pop(0)
                if e.text and len(e.text) > 0:
                    text_content = escape_for_html(e.text)
                    if len(out) + len(text_content) > MAX_OUTPUT_SIZE:
                        break
                    out += text_content
                processing[:0] = list(e)
                current_depth += 1
                element_count += 1

            RESPONSE += (
                f'Your XML doc results are: <br>{escape_for_html(out)}'
            )
        except Exception as e:
            logger.warning(f"XML parsing error: {type(e).__name__}", exc_info=False)
            RESPONSE += (
                f'There was an error reading your XML doc'
            )

        return RESPONSE, 200, SECURITY_HEADERS