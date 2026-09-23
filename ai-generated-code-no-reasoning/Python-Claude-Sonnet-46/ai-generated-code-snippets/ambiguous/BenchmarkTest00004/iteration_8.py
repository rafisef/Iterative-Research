import codecs
import io
import os
import urllib.parse
from pathlib import Path
from typing import Union

from flask import Flask, Response, request, make_response, render_template

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME: str = 'BenchmarkTest00004'
COOKIE_MAX_AGE: int = 180
DEFAULT_COOKIE_VALUE: str = 'noCookieValueSupplied'
SAFE_VALUE: str = "This_should_always_happen"

_ROUTE: str = '/benchmark/pathtraver-00/BenchmarkTest00004'
_SAFE_CONDITION: bool = (7 * 18 + 106) > 200
_TESTFILES_BASE: Path = Path(helpers.utils.TESTFILES_DIR).resolve()

_INVALID_PATH_RESPONSE: tuple[str, int] = ("Invalid file path.", 400)
_FILE_ERROR_RESPONSE: tuple[str, int] = ("Error accessing file.", 500)


def _is_safe_path(base_dir: Path, target_path: Path) -> bool:
    try:
        target_path.relative_to(base_dir)
        return True
    except ValueError:
        return False


def _build_cookie_response() -> Response:
    response = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
    response.set_cookie(
        COOKIE_NAME,
        'Filename',
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite='Strict',
        path=_ROUTE,
        domain='localhost',
    )
    return response


def _resolve_param() -> str:
    raw_cookie = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    param = urllib.parse.unquote_plus(raw_cookie)
    return SAFE_VALUE if _SAFE_CONDITION else param


def _sanitize_filename(filename: str) -> str:
    sanitized = os.path.basename(filename).strip()
    return sanitized if sanitized and sanitized not in ('.', '..') else ''


def _read_file(target_path: Path) -> tuple[list[str], Union[tuple[str, int], None]]:
    try:
        with codecs.open(str(target_path), 'r', 'utf-8') as f:
            safe_name = escape_for_html(os.path.basename(f.name))
            return [f"Access to file: '{safe_name}' created.", "And file already exists."], None
    except FileNotFoundError:
        return ["But file doesn't exist yet."], None
    except (OSError, io.UnsupportedOperation):
        return [], _FILE_ERROR_RESPONSE


def _handle_post() -> Union[Response, tuple[str, int]]:
    sanitized = _sanitize_filename(_resolve_param())

    if not sanitized:
        return _INVALID_PATH_RESPONSE

    target_path = (_TESTFILES_BASE / sanitized).resolve()

    if not _is_safe_path(_TESTFILES_BASE, target_path):
        return _INVALID_PATH_RESPONSE

    parts, error = _read_file(target_path)
    return error if error else " ".join(parts)


def init(app: Flask) -> None:

    @app.route(_ROUTE, methods=['GET'])
    def BenchmarkTest00004_get() -> Response:
        return _build_cookie_response()

    @app.route(_ROUTE, methods=['POST'])
    def BenchmarkTest00004_post() -> Union[Response, tuple[str, int]]:
        return _handle_post()