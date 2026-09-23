import codecs
import io
import os
import urllib.parse
from pathlib import Path
from typing import Union

from flask import Flask, Response, request, make_response, render_template

import helpers.utils
from helpers.utils import escape_for_html

COOKIE_NAME: str = "BenchmarkTest00004"
COOKIE_MAX_AGE: int = 180
DEFAULT_COOKIE_VALUE: str = "noCookieValueSupplied"
SAFE_VALUE: str = "This_should_always_happen"

_ROUTE: str = "/benchmark/pathtraver-00/BenchmarkTest00004"
_SAFE_CONDITION: bool = (7 * 18 + 106) > 200
_TESTFILES_BASE: Path = Path(helpers.utils.TESTFILES_DIR).resolve()

_INVALID_PATH_RESPONSE: tuple[str, int] = ("Invalid file path.", 400)
_FILE_ERROR_RESPONSE: tuple[str, int] = ("Error accessing file.", 500)

_TEMPLATE: str = "web/pathtraver-00/BenchmarkTest00004.html"

_FILE_EXISTS_MESSAGES: tuple[str, str] = (
    "Access to file: '{name}' created.",
    "And file already exists.",
)
_FILE_MISSING_MESSAGE: str = "But file doesn't exist yet."


def _is_safe_path(base: Path, target: Path) -> bool:
    try:
        target.relative_to(base)
        return True
    except ValueError:
        return False


def _build_cookie_response() -> Response:
    response = make_response(render_template(_TEMPLATE))
    response.set_cookie(
        COOKIE_NAME,
        "Filename",
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Strict",
        path=_ROUTE,
        domain="localhost",
    )
    return response


def _resolve_param() -> str:
    if _SAFE_CONDITION:
        return SAFE_VALUE
    raw = request.cookies.get(COOKIE_NAME, DEFAULT_COOKIE_VALUE)
    return urllib.parse.unquote_plus(raw)


def _sanitize_filename(filename: str) -> str:
    name = os.path.basename(filename).strip()
    return name if name and name not in (".", "..") else ""


def _read_file(path: Path) -> tuple[list[str], Union[tuple[str, int], None]]:
    try:
        with codecs.open(str(path), "r", "utf-8") as f:
            safe_name = escape_for_html(os.path.basename(f.name))
            messages = [
                _FILE_EXISTS_MESSAGES[0].format(name=safe_name),
                _FILE_EXISTS_MESSAGES[1],
            ]
            return messages, None
    except FileNotFoundError:
        return [_FILE_MISSING_MESSAGE], None
    except (OSError, io.UnsupportedOperation):
        return [], _FILE_ERROR_RESPONSE


def _handle_post() -> Union[Response, tuple[str, int]]:
    name = _sanitize_filename(_resolve_param())
    if not name:
        return _INVALID_PATH_RESPONSE

    target = (_TESTFILES_BASE / name).resolve()
    if not _is_safe_path(_TESTFILES_BASE, target):
        return _INVALID_PATH_RESPONSE

    parts, error = _read_file(target)
    if error:
        return error
    return " ".join(parts)


def init(app: Flask) -> None:
    @app.route(_ROUTE, methods=["GET"])
    def BenchmarkTest00004_get() -> Response:
        return _build_cookie_response()

    @app.route(_ROUTE, methods=["POST"])
    def BenchmarkTest00004_post() -> Union[Response, tuple[str, int]]:
        return _handle_post()