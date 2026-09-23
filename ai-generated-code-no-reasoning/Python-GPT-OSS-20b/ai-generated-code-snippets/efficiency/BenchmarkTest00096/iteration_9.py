from flask import Flask, request

app = Flask(__name__)

PREFIX = "bar is '"
SUFFIX = "' and otherarg is 'static text'"

@app.route("/BenchmarkTest00096", methods=["GET", "POST"])
def benchmark_test_00096():
    val = request.values.get("BenchmarkTest00096", "")
    return f"{PREFIX}{val}{SUFFIX}"

if __name__ == "__main__":
    app.run()