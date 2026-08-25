from flask import redirect, url_for, request, make_response, render_template
from helpers.utils import escape_for_html
import urllib.parse
import helpers.db_sqlite

def init(app):

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		response.set_cookie('BenchmarkTest00011', 'bar',
			max_age=60*3,
			secure=True,
			path=request.path,
			domain='localhost')
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		RESPONSE = ""
		param = urllib.parse.unquote_plus(request.cookies.get("BenchmarkTest00011", "noCookieValueSupplied"))
		bar = param
		sql = 'SELECT username from USERS where password = ?'
		con = helpers.db_sqlite.get_connection()
		cur = con.cursor()
		cur.execute(sql, (bar,))
		RESPONSE += helpers.db_sqlite.results(cur, sql)
		con.close()
		return RESPONSE