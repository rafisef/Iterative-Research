from flask import request, make_response
from helpers.utils import escape_for_html
import defusedxml.ElementTree as ET
import re
import html
import logging
import unicodedata
import secrets
import time

MAX_PARAM_LENGTH = 512
MAX_XML_DEPTH = 5
MAX_XML_NODES = 50
MAX_TEXT_NODES = 20
MAX_CONTENT_LENGTH = 32768
MAX_TAG_LENGTH = 64
MAX_ATTR_COUNT = 10
ALLOWED_XML_PATTERN = re.compile(r'^[\x20-\x7E]{1,512}$')
SAFE_XML_TAG_PATTERN = re.compile(r'^[a-zA-Z][a-zA-Z0-9_\-\.]{0,63}$')
SAFE_IP_PATTERN = re.compile(r'^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$|^(?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$')

logger = logging.getLogger(__name__)

_request_timestamps: dict = {}
_rate_limit_lock = __import__('threading').Lock()
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX = 30
RATE_LIMIT_CLEANUP_INTERVAL = 300
_last_cleanup_time = time.monotonic()


def _cleanup_rate_limit_store(now: float) -> None:
    global _last_cleanup_time
    if now - _last_cleanup_time < RATE_LIMIT_CLEANUP_INTERVAL:
        return
    window_start = now - RATE_LIMIT_WINDOW
    keys_to_delete = []
    for key, timestamps in _request_timestamps.items():
        if not any(t > window_start for t in timestamps):
            keys_to_delete.append(key)
    for key in keys_to_delete:
        del _request_timestamps[key]
    _last_cleanup_time = now


def _get_rate_limit_key(req) -> str:
    remote = req.remote_addr or 'unknown'
    forwarded = req.headers.get('X-Forwarded-For', '')
    if forwarded:
        ip = forwarded.split(',')[0].strip()[:45]
        if SAFE_IP_PATTERN.match(ip):
            return ip
    return remote


def _check_rate_limit(key: str) -> bool:
    now = time.monotonic()
    window_start = now - RATE_LIMIT_WINDOW
    with _rate_limit_lock:
        _cleanup_rate_limit_store(now)
        timestamps = _request_timestamps.get(key, [])
        timestamps = [t for t in timestamps if t > window_start]
        if len(timestamps) >= RATE_LIMIT_MAX:
            _request_timestamps[key] = timestamps
            return False
        timestamps.append(now)
        _request_timestamps[key] = timestamps
    return True


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
    normalized = content_type.lower().split(';')[0].strip()
    return normalized in ('application/x-www-form-urlencoded', 'multipart/form-data')


def _count_xml_depth(element, current_depth: int = 0) -> int:
    if current_depth > MAX_XML_DEPTH:
        return current_depth
    max_child_depth = current_depth
    for child in element:
        child_depth = _count_xml_depth(child, current_depth + 1)
        if child_depth > max_child_depth:
            max_child_depth = child_depth
    return max_child_depth


def _count_xml_nodes(element) -> int:
    count = 1
    for child in element:
        count += _count_xml_nodes(child)
        if count > MAX_XML_NODES:
            return count
    return count


def _validate_element(element, depth: int = 0) -> bool:
    if depth > MAX_XML_DEPTH:
        return False
    tag = element.tag
    if not isinstance(tag, str):
        return False
    if not SAFE_XML_TAG_PATTERN.match(tag):
        return False
    if len(element.attrib) > MAX_ATTR_COUNT:
        return False
    for attr_name, attr_value in element.attrib.items():
        if not isinstance(attr_name, str) or not isinstance(attr_value, str):
            return False
        if not SAFE_XML_TAG_PATTERN.match(attr_name):
            return False
        if len(attr_value) > MAX_PARAM_LENGTH:
            return False
    for child in element:
        if not _validate_element(child, depth + 1):
            return False
    return True


def check_xml_complexity(param: str) -> bool:
    depth = 0
    max_depth = 0
    node_count = 0
    i = 0
    while i < len(param):
        if param[i] == '<':
            if i + 1 < len(param) and param[i + 1] == '/':
                depth = max(0, depth - 1)
            elif i + 1 < len(param) and param[i + 1] not in ('?', '!'):
                node_count += 1
                depth += 1
                if node_count > MAX_XML_NODES:
                    return False
                if depth > max_depth:
                    max_depth = depth
                if max_depth > MAX_XML_DEPTH:
                    return False
        i += 1
    return True


def _contains_dangerous_patterns(param: str) -> bool:
    lower = param.lower()
    dangerous = [
        '<!entity', '<!doctype', 'system', 'public', 'notation',
        '<!element', '<!attlist', '<!notation', '%',
        'file://', 'http://', 'https://', 'ftp://', 'gopher://',
        'php://', 'data://', 'expect://', 'jar://',
        '\x00', '\x08', '\x0b', '\x0c', '\x0e', '\x0f',
        'xmlns', 'xlink', 'xinclude', 'xi:include',
        '&#', '&lt;', '&gt;', '&amp;', '&quot;', '&apos;',
        'cdata', '<![',
    ]
    return any(kw in lower for kw in dangerous)


def build_secure_response(body: str, status_code: int = 200) -> object:
    nonce = secrets.token_hex(32)
    response = make_response(body, status_code)
    response.headers['Content-Type'] = 'text/html; charset=utf-8'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        f"default-src 'none'; "
        f"script-src 'nonce-{nonce}'; "
        f"style-src 'nonce-{nonce}'; "
        f"base-uri 'none'; "
        f"form-action 'self'; "
        f"frame-ancestors 'none'; "
        f"object-src 'none'; "
        f"img-src 'none'; "
        f"connect-src 'none'; "
        f"font-src 'none'; "
        f"media-src 'none'; "
        f"worker-src 'none'"
    )
    response.headers['Strict-Transport-Security'] = 'max-age=63072000; includeSubDomains; preload'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Permissions-Policy'] = (
        'geolocation=(), microphone=(), camera=(), payment=(), '
        'usb=(), bluetooth=(), magnetometer=(), gyroscope=(), '
        'accelerometer=(), ambient-light-sensor=()'
    )
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    response.headers['Pragma'] = 'no-cache'
    response.headers['X-XSS-Protection'] = '0'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers.pop('Server', None)
    response.headers.pop('X-Powered-By', None)
    return response


def _safe_log(message: str) -> str:
    return re.sub(r'[\r\n\t]', '_', message)[:256]


def process_xml_param(param: str) -> tuple:
    if not param:
        return html.escape('No input provided.'), 400

    if len(param) > MAX_PARAM_LENGTH:
        logger.warning("XML input exceeded maximum length.")
        return html.escape('Input too large.'), 400

    if not ALLOWED_XML_PATTERN.match(param):
        logger.warning("Invalid characters detected in XML input.")
        return html.escape('Invalid characters detected in input.'), 400

    if _contains_dangerous_patterns(param):
        logger.warning("Potentially dangerous XML construct detected.")
        return html.escape('Disallowed XML construct detected.'), 400

    if not check_xml_complexity(param):
        logger.warning("XML input exceeded complexity limits.")
        return html.escape('XML input is too complex.'), 400

    try:
        root = ET.fromstring(
            param,
            forbid_dtd=True,
            forbid_entities=True,
            forbid_external=True
        )

        if not _validate_element(root):
            logger.warning("XML element failed structural validation.")
            return html.escape('Invalid XML structure detected.'), 400

        actual_depth = _count_xml_depth(root)
        if actual_depth > MAX_XML_DEPTH:
            logger.warning("XML depth exceeded after parsing.")
            return html.escape('XML input is too complex.'), 400

        actual_nodes = _count_xml_nodes(root)
        if actual_nodes > MAX_XML_NODES:
            logger.warning("XML node count exceeded after parsing.")
            return html.escape('XML input is too complex.'), 400

        text_parts = list(root.itertext())
        if len(text_parts) > MAX_TEXT_NODES:
            return html.escape('XML output too large.'), 400

        out = ''.join(text_parts)

        if len(out) > MAX_PARAM_LENGTH:
            out = out[:MAX_PARAM_LENGTH]

        out = re.sub(r'[^\x20-\x7E]', '', out)
        out = out.strip()

        safe_out = escape_for_html(out)

        if not safe_out or not safe_out.strip():
            return html.escape('No text content found in XML.'), 200

        return html.escape('Your XML doc results are: ') + '<br>' + safe_out, 200

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
        rate_key = _get_rate_limit_key(request)
        if not _check_rate_limit(rate_key):
            logger.warning("Rate limit exceeded for key: %s", _safe_log(rate_key))
            return build_secure_response(html.escape('Too many requests.'), 429)

        if not validate_content_type(request):
            return build_secure_response(html.escape('Unsupported Media Type.'), 415)

        content_length = request.content_length
        if content_length is not None:
            if content_length > MAX_CONTENT_LENGTH:
                return build_secure_response(html.escape('Request entity too large.'), 413)
            if content_length < 0:
                return build_secure_response(html.escape('Bad request.'), 400)
        else:
            return build_secure_response(html.escape('Bad request.'), 400)

        try:
            values = request.form.getlist("BenchmarkTest00205")
        except Exception:
            logger.warning("Failed to parse form data.")
            return build_secure_response(html.escape('Bad request.'), 400)

        if not values:
            return build_secure_response(html.escape('No input provided.'), 400)

        if len(values) > 1:
            logger.warning("Multiple values provided for parameter.")
            return build_secure_response(html.escape('Bad request.'), 400)

        raw_value = values[0]
        if not isinstance(raw_value, str):
            return build_secure_response(html.escape('Bad request.'), 400)

        if len(raw_value) > MAX_PARAM_LENGTH:
            return build_secure_response(html.escape('Input too large.'), 400)

        param = sanitize_param(raw_value)

        response_body, status_code = process_xml_param(param)
        return build_secure_response(response_body, status_code)