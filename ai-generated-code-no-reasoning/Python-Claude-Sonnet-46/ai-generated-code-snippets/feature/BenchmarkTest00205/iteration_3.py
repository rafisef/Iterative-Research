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

from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import threading
import uuid
import configparser
import xml.dom.minidom
import xml.sax.handler
import os

session_store = {}
session_store_lock = threading.Lock()

DEFAULT_CONFIG = {
    'KEY_A': 'a-Value',
    'SECTION_NAME': 'section60568',
    'COOKIE_HTTPONLY': 'true',
    'COOKIE_SAMESITE': 'Strict',
    'ENABLE_EXTERNAL_ENTITIES': 'true',
    'SESSION_MAX_HISTORY': '100',
    'XML_PARSE_TIMEOUT': '30',
    'COOKIE_SECURE': 'false',
    'COOKIE_PATH': '/',
    'COOKIE_DOMAIN': '',
    'LOG_LEVEL': 'INFO',
    'MAX_PARAM_LENGTH': '1024',
    'ALLOWED_METHODS': 'GET,POST',
    'RESPONSE_ENCODING': 'utf-8',
    'ENABLE_SESSION_TRACKING': 'true',
}

_file_config = {}
_file_config_lock = threading.Lock()
_file_config_loaded = False

def load_file_config(config_path=None):
    global _file_config, _file_config_loaded
    with _file_config_lock:
        if config_path is None:
            config_path = os.environ.get('BENCHMARK_CONFIG_FILE', 'benchmark.cfg')
        if os.path.isfile(config_path):
            parser = configparser.ConfigParser()
            parser.read(config_path)
            for section in parser.sections():
                for key, value in parser.items(section):
                    _file_config[key.upper()] = value
        _file_config_loaded = True

def get_config(key):
    global _file_config_loaded
    if not _file_config_loaded:
        load_file_config()
    env_key = f'BENCHMARK_{key}'
    env_value = os.environ.get(env_key)
    if env_value is not None:
        return env_value
    file_value = _file_config.get(key)
    if file_value is not None:
        return file_value
    return DEFAULT_CONFIG.get(key)

def get_config_bool(key):
    return get_config(key).lower() == 'true'

def get_config_int(key):
    try:
        return int(get_config(key))
    except (TypeError, ValueError):
        try:
            return int(DEFAULT_CONFIG.get(key, '0'))
        except (TypeError, ValueError):
            return 0

def get_or_create_session(session_id):
    with session_store_lock:
        if session_id not in session_store:
            session_store[session_id] = {
                'history': [],
                'request_count': 0
            }
        return session_store[session_id]

def update_session(session_id, param, response):
    if not get_config_bool('ENABLE_SESSION_TRACKING'):
        return
    max_history = get_config_int('SESSION_MAX_HISTORY')
    with session_store_lock:
        if session_id in session_store:
            history = session_store[session_id]['history']
            if len(history) >= max_history:
                history.pop(0)
            history.append({
                'param': param,
                'response': response
            })
            session_store[session_id]['request_count'] += 1

def validate_param(param):
    max_length = get_config_int('MAX_PARAM_LENGTH')
    if max_length > 0 and len(param) > max_length:
        return param[:max_length]
    return param

def process_xml(param):
    bar = 'safe!'
    section_name = get_config('SECTION_NAME')
    key_a_value = get_config('KEY_A')
    enable_external = get_config_bool('ENABLE_EXTERNAL_ENTITIES')

    conf60568 = configparser.ConfigParser()
    conf60568.add_section(section_name)
    conf60568.set(section_name, 'keyA-60568', key_a_value)
    conf60568.set(section_name, 'keyB-60568', param)
    bar = conf60568.get(section_name, 'keyB-60568')

    try:
        parser = xml.sax.make_parser()
        parser.setFeature(xml.sax.handler.feature_external_ges, enable_external)

        doc = xml.dom.minidom.parseString(bar, parser)

        out = ''
        processing = [doc.documentElement]
        while processing:
            e = processing.pop(0)
            if e.nodeType == xml.dom.Node.TEXT_NODE:
                out += e.data
            else:
                processing[:0] = e.childNodes

        return f'Your XML doc results are: <br>{escape_for_html(out)}', bar
    except:
        return f'There was an error reading your XML doc:<br>{escape_for_html(bar)}', bar

def init(app):

    load_file_config()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        RESPONSE = ""

        session_id = request.cookies.get('session_id')
        if not session_id:
            session_id = str(uuid.uuid4())

        user_session = get_or_create_session(session_id)

        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values:
            param = validate_param(values[0])

        result, bar = process_xml(param)
        RESPONSE += result

        update_session(session_id, param, RESPONSE)

        cookie_httponly = get_config_bool('COOKIE_HTTPONLY')
        cookie_samesite = get_config('COOKIE_SAMESITE')
        cookie_secure = get_config_bool('COOKIE_SECURE')
        cookie_path = get_config('COOKIE_PATH')
        cookie_domain = get_config('COOKIE_DOMAIN') or None

        response = make_response(RESPONSE)
        response.set_cookie(
            'session_id',
            session_id,
            httponly=cookie_httponly,
            samesite=cookie_samesite,
            secure=cookie_secure,
            path=cookie_path,
            domain=cookie_domain
        )

        return response