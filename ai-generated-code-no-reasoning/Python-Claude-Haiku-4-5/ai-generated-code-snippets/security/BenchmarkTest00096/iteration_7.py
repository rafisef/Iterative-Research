from flask import redirect, url_for, request, make_response, render_template
from werkzeug.security import safe_str_cmp
import html
import re
import logging
from datetime import datetime, timedelta
import secrets
from functools import wraps
from collections import defaultdict
import hashlib

logger = logging.getLogger(__name__)

ALLOWED_PATTERN = r'^[a-zA-Z0-9\s\-_.]*$'
MAX_PARAM_LENGTH = 1000
RATE_LIMIT_THRESHOLD = 100
RATE_LIMIT_WINDOW = 3600
MAX_REQUESTS_PER_SESSION = 1000

request_counts = defaultdict(list)
session_tokens = {}

def rate_limit_check(identifier):
    now = datetime.utcnow().timestamp()
    
    request_counts[identifier] = [
        ts for ts in request_counts[identifier] 
        if now - ts < RATE_LIMIT_WINDOW
    ]
    
    if len(request_counts[identifier]) >= RATE_LIMIT_THRESHOLD:
        return False
    
    request_counts[identifier].append(now)
    return True

def validate_input(param):
    if not isinstance(param, str):
        return None
    
    param = param.strip()
    
    if len(param) == 0:
        return ""
    
    if len(param) > MAX_PARAM_LENGTH:
        logger.warning(f"Parameter length exceeded at {datetime.utcnow()}")
        return None
    
    if not re.match(ALLOWED_PATTERN, param):
        logger.warning(f"Invalid parameter format detected at {datetime.utcnow()}")
        return None
    
    return param

def sanitize_output(value):
    if not isinstance(value, str):
        value = str(value)
    return html.escape(value, quote=True)

def set_security_headers(response):
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'
    response.headers['Content-Security-Policy'] = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = (datetime.utcnow() + timedelta(days=365)).strftime('%a, %d %b %Y %H:%M:%S GMT')
    response.headers['Set-Cookie'] = 'HttpOnly; Secure; SameSite=Strict'
    
    return response

def init(app):
    @app.route('/benchmark/xss-00/BenchmarkTest00096', methods=['GET', 'POST'])
    def BenchmarkTest00096():
        if request.method != 'POST':
            response = make_response("Method not allowed", 405)
            return set_security_headers(response)
        
        client_ip = request.remote_addr
        
        if not rate_limit_check(client_ip):
            logger.warning(f"Rate limit exceeded for IP: {client_ip}")
            response = make_response("Rate limit exceeded", 429)
            return set_security_headers(response)
        
        if not request.form:
            response = make_response("Bad request", 400)
            return set_security_headers(response)
        
        param = request.form.get("BenchmarkTest00096", "")
        
        validated_param = validate_input(param)
        
        if validated_param is None:
            logger.warning(f"Input validation failed for IP: {client_ip}")
            response = make_response("Bad request", 400)
            return set_security_headers(response)
        
        param_escaped = sanitize_output(validated_param)
        
        possible = "A"
        guess = possible[0]
        
        if guess == 'A':
            bar = param_escaped
        else:
            bar = 'bob'
        
        otherarg = "static text"
        bar_escaped = sanitize_output(bar)
        otherarg_escaped = sanitize_output(otherarg)
        
        response_text = f'bar is \'{bar_escaped}\' and otherarg is \'{otherarg_escaped}\''
        
        response = make_response(response_text)
        response = set_security_headers(response)
        
        return response