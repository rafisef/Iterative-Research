from flask import Flask, request

app = Flask(__name__)

PREFIX = "bar is '"
SUFFIX = "' and otherarg is 'static text'"

@app.route("/BenchmarkTest00096", methods=["GET", "POST"])
def benchmark_test_00096():
    return "".join((PREFIX, request.values.get("BenchmarkTest00096", ""), SUFFIX))