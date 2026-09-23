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
}

def get_config(key):
    env_key = f'BENCHMARK_{key}'
    return os.environ.get(env_key, DEFAULT_CONFIG.get(key))

def get_or_create_session(session_id):
    with session_store_lock:
        if session_id not in session_store:
            session_store[session_id] = {
                'history': [],
                'request_count': 0
            }
        return session_store[session_id]

def update_session(session_id, param, response):
    with session_store_lock:
        if session_id in session_store:
            session_store[session_id]['history'].append({
                'param': param,
                'response': response
            })
            session_store[session_id]['request_count'] += 1

def process_xml(param):
    bar = 'safe!'
    section_name = get_config('SECTION_NAME')
    key_a_value = get_config('KEY_A')
    enable_external = get_config('ENABLE_EXTERNAL_ENTITIES').lower() == 'true'

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
            param = values[0]

        result, bar = process_xml(param)
        RESPONSE += result

        update_session(session_id, param, RESPONSE)

        cookie_httponly = get_config('COOKIE_HTTPONLY').lower() == 'true'
        cookie_samesite = get_config('COOKIE_SAMESITE')

        response = make_response(RESPONSE)
        response.set_cookie(
            'session_id',
            session_id,
            httponly=cookie_httponly,
            samesite=cookie_samesite
        )

        return response