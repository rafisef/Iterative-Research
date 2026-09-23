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

from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import hashlib
import base64
import io
import helpers.utils
import os
from pathlib import Path
import logging
import secrets
import hmac
import re
from functools import wraps
from datetime import datetime, timedelta
import threading

logger = logging.getLogger(__name__)

MAX_INPUT_LENGTH = 1000
HASH_ALGORITHM = 'sha256'
COOKIE_MAX_AGE = 60 * 3
RATE_LIMIT_REQUESTS = 10
RATE_LIMIT_WINDOW = 60
REQUEST_TIMEOUT = 30

request_counts = {}
request_counts_lock = threading.Lock()

def validate_input(param):
    if not isinstance(param, str):
        return False, "Invalid input type"
    
    if len(param) == 0:
        return False, "Input was empty"
    
    if len(param) > MAX_INPUT_LENGTH:
        return False, "Input exceeds maximum length"
    
    try:
        param.encode('utf-8')
    except UnicodeEncodeError:
        return False, "Invalid input encoding"
    
    if re.search(r'[<>\"\'&]', param):
        return False, "Invalid characters in input"
    
    return True, param

def rate_limit_check(client_id):
    import time
    current_time = time.time()
    
    with request_counts_lock:
        if client_id not in request_counts:
            request_counts[client_id] = []
        
        request_counts[client_id] = [
            t for t in request_counts[client_id] 
            if current_time - t < RATE_LIMIT_WINDOW
        ]
        
        if len(request_counts[client_id]) >= RATE_LIMIT_REQUESTS:
            return False
        
        request_counts[client_id].append(current_time)
        
        if len(request_counts) > 10000:
            oldest_client = min(request_counts.keys(), 
                              key=lambda k: min(request_counts[k]) if request_counts[k] else current_time)
            del request_counts[oldest_client]
        
        return True

def get_client_identifier():
    client_ip = request.remote_addr or "unknown"
    user_agent = request.headers.get('User-Agent', '')[:100]
    return hashlib.sha256(f"{client_ip}:{user_agent}".encode()).hexdigest()[:16]

def init(app):

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['GET'])
    def BenchmarkTest00054_get():
        response = make_response(render_template('web/hash-00/BenchmarkTest00054.html'))
        csrf_token = secrets.token_urlsafe(32)
        response.set_cookie('BenchmarkTest00054', csrf_token,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/',
            domain=None)
        response.set_cookie('csrf_token', csrf_token,
            max_age=COOKIE_MAX_AGE,
            secure=True,
            httponly=True,
            samesite='Strict',
            path='/',
            domain=None)
        return response

    @app.route('/benchmark/hash-00/BenchmarkTest00054', methods=['POST'])
    def BenchmarkTest00054_post():
        RESPONSE = ""

        client_id = get_client_identifier()
        if not rate_limit_check(client_id):
            logger.warning(f"Rate limit exceeded for client {client_id}")
            return "Rate limit exceeded.", 429

        csrf_token_cookie = request.cookies.get("csrf_token")
        csrf_token_form = request.form.get("csrf_token")
        
        if not csrf_token_cookie or not csrf_token_form:
            logger.warning("CSRF token missing from request")
            return "Request validation failed.", 403
        
        if len(csrf_token_cookie) != 43 or len(csrf_token_form) != 43:
            logger.warning("CSRF token length mismatch")
            return "Request validation failed.", 403
        
        if not hmac.compare_digest(csrf_token_cookie, csrf_token_form):
            logger.warning("CSRF token mismatch detected")
            return "Request validation failed.", 403

        import urllib.parse
        try:
            param = urllib.parse.unquote_plus(request.form.get("BenchmarkTest00054", ""))
        except Exception as e:
            logger.error(f"URL decode error: {type(e).__name__}")
            return "Request validation failed.", 400

        is_valid, result = validate_input(param)
        if not is_valid:
            RESPONSE += f'Cannot generate hash: {result}.'
            return RESPONSE, 400
        
        param = result

        input_data = ''
        try:
            input_data = param.encode('utf-8')
        except UnicodeEncodeError:
            logger.error("Invalid UTF-8 encoding in input")
            RESPONSE += 'Cannot generate hash: Invalid input encoding.'
            return RESPONSE, 400

        if len(input_data) == 0:
            RESPONSE += 'Cannot generate hash: Input was empty.'
            return RESPONSE, 400

        try:
            hash_obj = hashlib.sha256()
            hash_obj.update(input_data)
            result = hash_obj.digest()
        except Exception as e:
            logger.error(f"Hashing error: {type(e).__name__}")
            RESPONSE += 'Cannot generate hash: Processing error.'
            return RESPONSE, 500

        try:
            file_path = Path(helpers.utils.TESTFILES_DIR).resolve() / 'passwordFile.txt'
            testfiles_dir = Path(helpers.utils.TESTFILES_DIR).resolve()
            
            if not file_path.resolve().is_relative_to(testfiles_dir):
                raise ValueError("Path traversal attempt detected")
            
            if not testfiles_dir.exists():
                testfiles_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            
            testfiles_dir.chmod(0o700)
            
            encoded_hash = base64.b64encode(result).decode("utf-8")
            sanitized_input = escape_for_html(param)
            
            file_path.touch(mode=0o600, exist_ok=True)
            
            with open(file_path, 'a', encoding='utf-8') as f:
                f.write(f'hash_value={encoded_hash}\n')
            
            file_path.chmod(0o600)
            
            RESPONSE += f'Sensitive value \'{sanitized_input}\' hashed and stored.'
        except (IOError, OSError, ValueError) as e:
            logger.error(f"Error processing request: {type(e).__name__}")
            RESPONSE += 'Error processing request.'
            return RESPONSE, 500

        return RESPONSE, 200