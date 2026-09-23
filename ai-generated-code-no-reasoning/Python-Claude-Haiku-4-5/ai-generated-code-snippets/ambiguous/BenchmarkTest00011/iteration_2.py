from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite


def init(app):
	COOKIE_NAME = 'BenchmarkTest00011'
	COOKIE_DEFAULT = 'noCookieValueSupplied'
	COOKIE_MAX_AGE = 60 * 3
	ROUTE_BASE = '/benchmark/sqli-00/BenchmarkTest00011'
	TEMPLATE_PATH = 'web/sqli-00/BenchmarkTest00011.html'

	@app.route(ROUTE_BASE, methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template(TEMPLATE_PATH))
		response.set_cookie(
			COOKIE_NAME,
			'bar',
			max_age=COOKIE_MAX_AGE,
			secure=True,
			path=ROUTE_BASE,
			domain='localhost',
			httponly=True,
			samesite='Strict'
		)
		return response

	@app.route(ROUTE_BASE, methods=['POST'])
	def BenchmarkTest00011_post():
		param = urllib.parse.unquote_plus(
			request.cookies.get(COOKIE_NAME, COOKIE_DEFAULT)
		)

		sql = 'SELECT username FROM USERS WHERE password = ?'
		con = helpers.db_sqlite.get_connection()
		try:
			cur = con.cursor()
			cur.execute(sql, (param,))
			response = helpers.db_sqlite.results(cur, sql)
		finally:
			con.close()

		return response