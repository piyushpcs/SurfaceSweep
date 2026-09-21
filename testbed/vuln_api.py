from flask import Flask, jsonify, request
import os

app = Flask(__name__)

SECRET_API_KEY = os.environ.get("SECRET_API_KEY", "FAKE_STRIPE_KEY_for_testing_only_12345")

@app.route("/")
def index():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Test App</title></head>
    <body>
    <script src="/static/app.js"></script>
    <script>
        var config = {
            api_key: "FAKE_AWS_KEY_for_testing_12345",
            secret: "supersecretvalue12345",
            bearer: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
        };
        fetch("/api/v2/users");
        fetch("/api/v2/admin/settings");
        axios.get("/api/v2/products");
    </script>
    </body>
    </html>
    """

@app.route("/static/app.js")
def app_js():
    return """
    // Main application bundle
    var BASE_URL = "https://api.testapp.local";
    fetch(BASE_URL + "/api/v2/auth/login");
    axios.post("/api/v2/orders", {item: "test"});
    $.ajax({url: "/api/v2/search"});
    $.get("/api/v2/health");

    // Hidden admin endpoints
    var adminPath = "/admin/debug/config";
    var token = "ghp_FAKE_GITHUB_TOKEN_for_testing_12345";
    var gitlab = "glpat-FAKE_GITLAB_TOKEN_12345";
    var npm_token = "npm_FAKE_NPM_TOKEN_for_testing_1234";
    var firebase_url = "https://myproject.firebaseio.com";

    // Environment variables leaked
    var NEXT_PUBLIC_API_URL = "https://api.testapp.local/v3";
    var REACT_APP_SECRET_KEY = "value123456789";

    // Webpack chunks
    import("./chunk-abc123.js");
    import("./vendor.def456.js");
    """

@app.route("/static/chunk-abc123.js")
def chunk_js():
    return """
    // Chunk file
    fetch("/api/v2/chunk-data");
    axios.get("/api/v2/analytics");
    """

@app.route("/static/vendor.def456.js")
def vendor_js():
    return """
    // Vendor chunk
    fetch("/api/v2/vendor-endpoint");
    """

@app.route("/api/v2/<path:path>", methods=["GET", "POST"])
def api_catchall(path):
    return jsonify({"status": "ok", "path": path})

if __name__ == "__main__":
    app.run(port=5555, debug=True)
