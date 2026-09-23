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
import time
import hashlib
import hmac
import collections

session_store = {}
session_store_lock = threading.RLock()
session_activity = {}
session_user_map = {}
active_sessions_per_user = collections.defaultdict(set)

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
    'SESSION_TIMEOUT': '3600',
    'MAX_CONCURRENT_SESSIONS_PER_USER': '10',
    'SESSION_CLEANUP_INTERVAL': '300',
    'SESSION_TOKEN_SECRET': 'default-secret-change-me',
    'MAX_TOTAL_SESSIONS': '10000',
}

_file_config = {}
_file_config_lock = threading.Lock()
_file_config_loaded = False
_cleanup_timer = None
_cleanup_timer_lock = threading.Lock()

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

def generate_session_token(session_id):
    secret = get_config('SESSION_TOKEN_SECRET').encode('utf-8')
    token = hmac.new(secret, session_id.encode('utf-8'), hashlib.sha256).hexdigest()
    return token

def validate_session_token(session_id, token):
    expected = generate_session_token(session_id)
    return hmac.compare_digest(expected, token)

def _schedule_cleanup():
    global _cleanup_timer
    with _cleanup_timer_lock:
        if _cleanup_timer is not None:
            _cleanup_timer.cancel()
        interval = get_config_int('SESSION_CLEANUP_INTERVAL')
        if interval <= 0:
            interval = 300
        _cleanup_timer = threading.Timer(interval, _run_cleanup)
        _cleanup_timer.daemon = True
        _cleanup_timer.start()

def _run_cleanup():
    cleanup_expired_sessions()
    _schedule_cleanup()

def cleanup_expired_sessions():
    timeout = get_config_int('SESSION_TIMEOUT')
    now = time.time()
    expired = []
    with session_store_lock:
        for sid, last_active in list(session_activity.items()):
            if now - last_active > timeout:
                expired.append(sid)
        for sid in expired:
            _remove_session_locked(sid)

def _remove_session_locked(session_id):
    session_store.pop(session_id, None)
    session_activity.pop(session_id, None)
    user_id = session_user_map.pop(session_id, None)
    if user_id is not None:
        active_sessions_per_user[user_id].discard(session_id)
        if not active_sessions_per_user[user_id]:
            del active_sessions_per_user[user_id]

def evict_oldest_session_for_user(user_id):
    sessions = list(active_sessions_per_user.get(user_id, set()))
    if not sessions:
        return
    oldest = min(sessions, key=lambda s: session_activity.get(s, float('inf')))
    _remove_session_locked(oldest)

def get_or_create_session(session_id, user_id=None, token=None):
    now = time.time()
    timeout = get_config_int('SESSION_TIMEOUT')
    max_per_user = get_config_int('MAX_CONCURRENT_SESSIONS_PER_USER')
    max_total = get_config_int('MAX_TOTAL_SESSIONS')

    with session_store_lock:
        if session_id in session_store:
            last_active = session_activity.get(session_id, 0)
            if timeout > 0 and now - last_active > timeout:
                _remove_session_locked(session_id)
            else:
                if token is not None and not validate_session_token(session_id, token):
                    _remove_session_locked(session_id)
                else:
                    session_activity[session_id] = now
                    return session_store[session_id], session_id, False

        new_session_id = str(uuid.uuid4())
        resolved_user_id = user_id or new_session_id

        if max_per_user > 0:
            user_sessions = active_sessions_per_user.get(resolved_user_id, set())
            while len(user_sessions) >= max_per_user:
                evict_oldest_session_for_user(resolved_user_id)
                user_sessions = active_sessions_per_user.get(resolved_user_id, set())

        if max_total > 0 and len(session_store) >= max_total:
            if session_store:
                oldest_global = min(session_activity, key=session_activity.get)
                _remove_session_locked(oldest_global)

        session_store[new_session_id] = {
            'history': [],
            'request_count': 0,
            'created_at': now,
            'user_id': resolved_user_id,
            'concurrent_lock': threading.Lock(),
        }
        session_activity[new_session_id] = now
        session_user_map[new_session_id] = resolved_user_id
        active_sessions_per_user[resolved_user_id].add(new_session_id)

        return session_store[new_session_id], new_session_id, True

def touch_session(session_id):
    with session_store_lock:
        if session_id in session_store:
            session_activity[session_id] = time.time()

def update_session(session_id, param, response):
    if not get_config_bool('ENABLE_SESSION_TRACKING'):
        return
    max_history = get_config_int('SESSION_MAX_HISTORY')
    with session_store_lock:
        if session_id in session_store:
            sess = session_store[session_id]
            concurrent_lock = sess.get('concurrent_lock')

    if concurrent_lock is None:
        return

    with concurrent_lock:
        with session_store_lock:
            if session_id not in session_store:
                return
            sess = session_store[session_id]

        history = sess['history']
        if len(history) >= max_history:
            history.pop(0)
        history.append({
            'param': param,
            'response': response,
            'timestamp': time.time(),
        })
        sess['request_count'] += 1

def get_session_info(session_id):
    with session_store_lock:
        if session_id not in session_store:
            return None
        sess = session_store[session_id]
        user_id = sess.get('user_id')
        concurrent_count = len(active_sessions_per_user.get(user_id, set()))
        return {
            'session_id': session_id,
            'user_id': user_id,
            'request_count': sess['request_count'],
            'created_at': sess.get('created_at'),
            'last_active': session_activity.get(session_id),
            'concurrent_sessions': concurrent_count,
        }

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
    _schedule_cleanup()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['GET'])
    def BenchmarkTest00205_get():
        return BenchmarkTest00205_post()

    @app.route('/benchmark/xxe-00/BenchmarkTest00205', methods=['POST'])
    def BenchmarkTest00205_post():
        RESPONSE = ""

        session_id = request.cookies.get('session_id')
        session_token = request.cookies.get('session_token')
        user_id = request.headers.get('X-User-ID') or request.cookies.get('user_id')

        user_session, active_session_id, is_new = get_or_create_session(
            session_id or '',
            user_id=user_id,
            token=session_token,
        )

        values = request.form.getlist("BenchmarkTest00205")
        param = ""
        if values:
            param = validate_param(values[0])

        result, bar = process_xml(param)
        RESPONSE += result

        update_session(active_session_id, param, RESPONSE)
        touch_session(active_session_id)

        cookie_httponly = get_config_bool('COOKIE_HTTPONLY')
        cookie_samesite = get_config('COOKIE_SAMESITE')
        cookie_secure = get_config_bool('COOKIE_SECURE')
        cookie_path = get_config('COOKIE_PATH')
        cookie_domain = get_config('COOKIE_DOMAIN') or None
        session_timeout = get_config_int('SESSION_TIMEOUT')
        new_token = generate_session_token(active_session_id)

        response = make_response(RESPONSE)
        response.set_cookie(
            'session_id',
            active_session_id,
            httponly=cookie_httponly,
            samesite=cookie_samesite,
            secure=cookie_secure,
            path=cookie_path,
            domain=cookie_domain,
            max_age=session_timeout if session_timeout > 0 else None,
        )
        response.set_cookie(
            'session_token',
            new_token,
            httponly=cookie_httponly,
            samesite=cookie_samesite,
            secure=cookie_secure,
            path=cookie_path,
            domain=cookie_domain,
            max_age=session_timeout if session_timeout > 0 else None,
        )

        return response