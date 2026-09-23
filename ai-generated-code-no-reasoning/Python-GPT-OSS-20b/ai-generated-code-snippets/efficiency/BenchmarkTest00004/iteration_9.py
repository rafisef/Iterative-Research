def init(app):
    import os
    from flask import request, make_response, render_template
    from helpers.utils import escape_for_html, TESTFILES_DIR

    path = os.path.join(TESTFILES_DIR, 'This_should_always_happen')

    @app.route('/benchmark/pathtraver-00/BenchmarkTest00004', methods=['GET', 'POST'])
    def benchmark_test():
        if request.method == 'GET':
            resp = make_response(render_template('web/pathtraver-00/BenchmarkTest00004.html'))
            resp.set_cookie('BenchmarkTest00004', 'Filename', max_age=180, secure=True,
                            path=request.path, domain='localhost')
            return resp
        if os.path.exists(path):
            return f"Access to file: '{escape_for_html(path)}' created. And file already exists."
        return "But file doesn't exist yet."