from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite


def init(app):
	COOKIE_NAME = 'BenchmarkTest00011'
	COOKIE_DEFAULT = 'noCookieValueSupplied'
	COOKIE_CONFIG = {
		'max_age': 180,
		'secure': True,
		'path': '/benchmark/sqli-00/BenchmarkTest00011',
		'domain': 'localhost',
		'httponly': True,
		'samesite': 'Strict'
	}
	ROUTE_BASE = '/benchmark/sqli-00/BenchmarkTest00011'
	TEMPLATE_PATH = 'web/sqli-00/BenchmarkTest00011.html'

	def _get_db_results(param):
		sql = 'SELECT username FROM USERS WHERE password = ?'
		con = helpers.db_sqlite.get_connection()
		try:
			cur = con.cursor()
			cur.execute(sql, (param,))
			return helpers.db_sqlite.results(cur, sql)
		finally:
			con.close()

	@app.route(ROUTE_BASE, methods=['GET', 'POST'])
	def BenchmarkTest00011():
		if request.method == 'GET':
			response = make_response(render_template(TEMPLATE_PATH))
			response.set_cookie(COOKIE_NAME, 'bar', **COOKIE_CONFIG)
			return response
		
		param = urllib.parse.unquote_plus(
			request.cookies.get(COOKIE_NAME, COOKIE_DEFAULT)
		)
		return _get_db_results(param)