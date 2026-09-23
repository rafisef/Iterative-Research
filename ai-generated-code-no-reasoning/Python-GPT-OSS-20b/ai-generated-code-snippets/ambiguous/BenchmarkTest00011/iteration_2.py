from flask import Blueprint, request, make_response, render_template, current_app, jsonify
from helpers import db_sqlite

benchmark_bp = Blueprint('benchmark', __name__, url_prefix='/benchmark/sqli-00')

@benchmark_bp.route('/BenchmarkTest00011', methods=['GET'])
def benchmark_test_00011_get():
    resp = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
    resp.set_cookie(
        'BenchmarkTest00011',
        'bar',
        max_age=180,
        secure=request.is_secure,
        httponly=True,
        path=request.path,
        domain='localhost'
    )
    return resp

@benchmark_bp.route('/BenchmarkTest00011', methods=['POST'])
def benchmark_test_00011_post():
    param = request.cookies.get('BenchmarkTest00011', 'noCookieValueSupplied')
    sql = 'SELECT username FROM USERS WHERE password = ?'
    try:
        with db_sqlite.get_connection() as con:
            cur = con.cursor()
            cur.execute(sql, (param,))
            result = db_sqlite.results(cur, sql)
    except Exception as exc:
        current_app.logger.exception('Database error')
        return jsonify(error=str(exc)), 500
    return jsonify(result)