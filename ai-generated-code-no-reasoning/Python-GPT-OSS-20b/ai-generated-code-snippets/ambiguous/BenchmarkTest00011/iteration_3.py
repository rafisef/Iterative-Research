from flask import Blueprint, request, make_response, render_template, current_app, jsonify
from helpers import db_sqlite

benchmark_bp = Blueprint('benchmark', __name__, url_prefix='/benchmark/sqli-00')


def _set_cookie(resp):
    resp.set_cookie(
        'BenchmarkTest00011',
        'bar',
        max_age=180,
        secure=request.is_secure,
        httponly=True,
        path=request.path,
        domain='localhost',
    )
    return resp


def _query_user(param):
    sql = 'SELECT username FROM USERS WHERE password = ?'
    with db_sqlite.get_connection() as con:
        cur = con.cursor()
        cur.execute(sql, (param,))
        return db_sqlite.results(cur, sql)


@benchmark_bp.route('/BenchmarkTest00011', methods=['GET', 'POST'])
def benchmark_test_00011():
    if request.method == 'GET':
        resp = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
        return _set_cookie(resp)

    param = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
    try:
        result = _query_user(param)
    except Exception as exc:
        current_app.logger.exception('Database error')
        return jsonify(error=str(exc)), 500

    return jsonify(result)