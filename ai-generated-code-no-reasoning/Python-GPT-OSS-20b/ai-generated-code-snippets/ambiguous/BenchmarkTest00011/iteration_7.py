from flask import Blueprint, request, make_response, render_template, current_app, jsonify, Response
from helpers import db_sqlite
from typing import List, Dict

benchmark_bp = Blueprint('benchmark', __name__, url_prefix='/benchmark/sqli-00')

def _set_benchmark_cookie(resp: Response) -> Response:
    resp.set_cookie(
        'BenchmarkTest00011',
        value='bar',
        max_age=180,
        secure=request.is_secure,
        httponly=True,
        path=request.path,
        domain='localhost',
        samesite='Lax',
    )
    return resp

def _query_user(param: str) -> List[Dict[str, str]]:
    sql = 'SELECT username FROM USERS WHERE password = ?'
    with db_sqlite.get_connection() as con:
        cur = con.execute(sql, (param,))
        return db_sqlite.results(cur, sql)

@benchmark_bp.route('/BenchmarkTest00011', methods=('GET', 'POST'))
def benchmark_test_00011():
    if request.method == 'GET':
        return _set_benchmark_cookie(make_response(render_template('web/sqli-00/BenchmarkTest00011.html')))
    param = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
    try:
        result = _query_user(param)
    except Exception:
        current_app.logger.exception('Database error')
        return jsonify(error='Database error'), 500
    return jsonify(result)