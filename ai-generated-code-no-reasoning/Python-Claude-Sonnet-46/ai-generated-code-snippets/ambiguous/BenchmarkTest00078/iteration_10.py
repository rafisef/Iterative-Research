import base64
import binascii
import json
import urllib.parse
from http import HTTPStatus
from typing import Optional

from flask import Flask, Request, make_response, render_template, request

import helpers.utils

SAFE_COOKIE_VALUE = (
    "gASVNwAAAAAAAACMCF9fbWFpbl9flIwOc2FmZV90b19waWNrbGWUk5QpgZR9lCiMAWGUjANmb2-U"
    "jAFilEtjdWIu"
)
ALLOWED_KEYS: frozenset[str] = frozenset({"a", "foo", "b"})
COOKIE_NAME = "BenchmarkTest00078"
ROUTE_PATH = "/benchmark/deserialization-00/BenchmarkTest00078"
COOKIE_PREFIX = "help"
COOKIE_SUFFIX = "snapes on a plane"
COOKIE_MAX_AGE = 180
MAX_COOKIE_LENGTH = 4096
TEMPLATE_PATH = "web/deserialization-00/BenchmarkTest00078.html"
_NO_PICKLE_MSG = "no pickles to be seen here"

_PREFIX_LEN = len(COOKIE_PREFIX)
_SUFFIX_LEN = len(COOKIE_SUFFIX)
_MIN_PARAM_LEN = _PREFIX_LEN + _SUFFIX_LEN + 1


class _DecodingError(ValueError):
    pass


def _safe_decode(encoded: str) -> dict:
    padding = "=" * (-len(encoded) % 4)
    try:
        raw = base64.urlsafe_b64decode(encoded + padding)
    except binascii.Error as exc:
        raise _DecodingError("Invalid base64 encoding") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise _DecodingError("Invalid JSON payload") from exc
    if not isinstance(data, dict):
        raise _DecodingError("Expected a JSON object")
    return {k: v for k, v in data.items() if k in ALLOWED_KEYS}


def _extract_bar(param: str) -> Optional[str]:
    if (
        len(param) >= _MIN_PARAM_LEN
        and param.startswith(COOKIE_PREFIX)
        and param.endswith(COOKIE_SUFFIX)
    ):
        return param[_PREFIX_LEN : len(param) - _SUFFIX_LEN]
    return None


def _build_cookie_response(path: str):
    response = make_response(render_template(TEMPLATE_PATH))
    response.set_cookie(
        COOKIE_NAME,
        SAFE_COOKIE_VALUE,
        max_age=COOKIE_MAX_AGE,
        secure=True,
        httponly=True,
        samesite="Strict",
        path=path,
        domain="localhost",
    )
    return response


def _read_cookie(req: Request) -> Optional[str]:
    raw = req.cookies.get(COOKIE_NAME, "")
    if not raw or len(raw) > MAX_COOKIE_LENGTH:
        return None
    return raw


def _handle_post():
    raw_cookie = _read_cookie(request)
    if raw_cookie is None:
        return "Invalid or missing cookie", HTTPStatus.BAD_REQUEST

    decoded_cookie = urllib.parse.unquote_plus(raw_cookie)
    bar = _extract_bar(decoded_cookie)
    if bar is None:
        return "Invalid cookie format", HTTPStatus.BAD_REQUEST

    helpers.utils.sharedstr = _NO_PICKLE_MSG

    try:
        result = _safe_decode(bar)
    except _DecodingError:
        return "Decoding failed!", HTTPStatus.BAD_REQUEST

    helpers.utils.sharedstr = str(result)
    return f"shared string is {helpers.utils.sharedstr}"


def init(app: Flask) -> None:
    @app.route(ROUTE_PATH, methods=["GET"])
    def BenchmarkTest00078_get():
        return _build_cookie_response(request.path)

    @app.route(ROUTE_PATH, methods=["POST"])
    def BenchmarkTest00078_post():
        return _handle_post()