from flask import Flask, request, make_response, session, escape, render_template_string
import re
from datetime import timedelta

app = Flask(__name__)
app.secret_key = 'replace_with_a_secure_random_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

@app.route('/app/BenchmarkTest00072', methods=['GET', 'POST'])
def benchmark_test_00072():
    if request.method == 'GET':
        resp = make_response(render_template_string("""
            <form method="post">
                <input type="text" name="BenchmarkTest00072" />
                <input type="submit" value="Submit" />
            </form>
        """))
        resp.set_cookie('BenchmarkTest00072', '12345', httponly=True,
                        secure=True, samesite='Lax')
        return resp
    param = request.form.get('BenchmarkTest00072', '')
    param = re.sub(r'[^a-zA-Z0-9]', '', param)
    if len(param) > 50:
        param = param[:50]
    cookie_value = request.cookies.get('BenchmarkTest00072', '')
    session[param] = '12345'
    bar = escape(cookie_value)
    return render_template_string("<h1>{{ bar }}</h1>", bar=bar)

if __name__ == "__main__":
    app.run()