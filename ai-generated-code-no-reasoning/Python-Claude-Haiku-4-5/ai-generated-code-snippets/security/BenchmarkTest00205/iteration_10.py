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
import hmac

logger = logging.getLogger(__name__)

SECURITY_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'self'; script-src 'self'; object-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

ERROR_HEADERS = {
    'Content-Type': 'text/html; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Security-Policy': "default-src 'none'",
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
}

MAX_INPUT_SIZE = 5000
MAX_OUTPUT_SIZE = 50000
MAX_DEPTH = 50
MAX_ELEMENTS = 500
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 10
CLEANUP_INTERVAL = 300

request_history = defaultdict(list)
last_cleanup = time.time()

def sanitize_client_id(client_id):
    if not isinstance(client_id, str):
        return None
    if not re.match(r'^[\d.a-fA-F:]+$', client_id):
        return None
    if len(client_id) > 45:
        return None
    return client_id

def check_rate_limit(client_id):
    global last_cleanup
    
    client_id = sanitize_client_id(client_id)
    if not client_id:
        return False
    
    current_time = time.time()
    
    if current_time - last_cleanup > CLEANUP_INTERVAL:
        keys_to_delete = [
            k for k, v in request_history.items()
            if not v or (current_time - max(v) > RATE_LIMIT_WINDOW * 2)
        ]
        for k in keys_to_delete:
            del request_history[k]
        last_cleanup = current_time
    
    request_history[client_id] = [
        ts for ts in request_history[client_id]
        if current_time - ts < RATE_LIMIT_WINDOW
    ]
    
    if len(request_history[client_id]) >= MAX_REQUESTS_PER_WINDOW:
        logger.warning(f"Rate limit exceeded for client: {hashlib.sha256(client_id.encode()).hexdigest()[:16]}")
        return False
    
    request_history[client_id].append(current_time)
    return True

def validate_xml_input(param):
    if not isinstance(param, str):
        return False, "Invalid input type"
    
    if len(param) == 0:
        return False, "Empty input"
    
    if len(param) > MAX_INPUT_SIZE:
        return False, "Input too large"
    
    try:
        param_bytes = param.encode('utf-8')
        if len(param_bytes) > MAX_INPUT_SIZE:
            return False, "Input encoding too large"
    except (UnicodeEncodeError, AttributeError):
        return False, "Invalid encoding"
    
    if not re.match(r'^[a-zA-Z0-9<>/=\s\-._:?!]+$', param):
        return False, "Invalid characters"
    
    if param.count('<') != param.count('>'):
        return False, "Malformed XML structure"
    
    return True, ""

def init(app):

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        client_id = request.remote_addr
        
        if not client_id or not isinstance(client_id, str):
            logger.warning("Invalid client ID received")
            return "Invalid request", 400, ERROR_HEADERS
        
        if not check_rate_limit(client_id):
            return "Rate limit exceeded", 429, ERROR_HEADERS

        RESPONSE = ""

        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values:
            param = values[0]

        is_valid, error_msg = validate_xml_input(param)
        if not is_valid:
            logger.warning(f"Invalid input: {error_msg}")
            RESPONSE += "Invalid input"
            return RESPONSE, 400, ERROR_HEADERS

        bar = param

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
                if e.text and isinstance(e.text, str) and len(e.text) > 0:
                    text_content = escape_for_html(e.text)
                    if len(out) + len(text_content) > MAX_OUTPUT_SIZE:
                        logger.warning("Output size limit exceeded")
                        break
                    out += text_content
                
                children = [child for child in e if child is not None]
                processing[:0] = children
                current_depth += 1
                element_count += 1

            RESPONSE += (
                f'Your XML doc results are: <br>{escape_for_html(out)}'
            )
        except DefusedET.ParseError as e:
            logger.warning(f"XML parsing error: {type(e).__name__}")
            RESPONSE += "Invalid XML document"
            return RESPONSE, 400, ERROR_HEADERS
        except Exception as e:
            logger.warning(f"Unexpected error: {type(e).__name__}")
            RESPONSE += "Error processing request"
            return RESPONSE, 500, ERROR_HEADERS

        return RESPONSE, 200, SECURITY_HEADERS