from flask import redirect, url_for, request, make_response, render_template, session
from helpers.utils import escape_for_html
import threading

def init(app):
	app.secret_key = 'benchmark-secret-key'
	session_lock = threading.Lock()

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['GET'])
	def BenchmarkTest00011_get():
		with session_lock:
			session['BenchmarkTest00011'] = 'bar'
		response = make_response(render_template('web/sqli-00/BenchmarkTest00011.html'))
		return response

	@app.route('/benchmark/sqli-00/BenchmarkTest00011', methods=['POST'])
	def BenchmarkTest00011_post():
		RESPONSE = ""

		param = session.get("BenchmarkTest00011", "noCookieValueSupplied")

		bar = "This should never happen"
		if 'should' in bar:
			bar = param

		storage_type = request.args.get("storage", "database")
		if storage_type == "file":
			with open("results.txt", "a") as f:
				f.write(bar)
			RESPONSE += "file stored"
		else:
			import helpers.db_sqlite

			sql = f'SELECT username from USERS where password = ?'
			con = helpers.db_sqlite.get_connection()
			cur = con.cursor()
			cur.execute(sql, (bar,))
			RESPONSE += (
				helpers.db_sqlite.results(cur, sql)
			)
			con.close()

		return RESPONSE