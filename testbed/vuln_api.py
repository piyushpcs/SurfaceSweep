from flask import Flask, jsonify, request
import os

app = Flask(__name__)

@app.route("/")
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Test App</title></head>
    <body>
    <script src="/static/app.js"></script>
    <script>
    fetch("/api/v2/users");
    fetch("/api/v2/admin/settings");
    axios.get("/api/v2/products");
    fetch("/api/v1/public");
    fetch("/api/v2/null-cred");
    fetch("/api/v2/legit");
    </script>
    </body>
    </html>
    '''

@app.route("/static/app.js")
def app_js():
    return r'''
    var BASE_URL = "https://api.testapp.local";
    fetch(BASE_URL + "/api/v2/auth/login");
    axios.post("/api/v2/orders", {item: "test"});
    $.ajax({url: "/api/v2/search"});
    $.get("/api/v2/health");
    var adminPath = "/admin/debug/config";
    var token = "ghp_FAKE_GITHUB_TOKEN_for_testing_12345";
    var NEXT_PUBLIC_API_URL = "https://api.testapp.local/v3";
    var REACT_APP_SECRET_KEY = "value123456789";
    import("./chunk-abc123.js");
    import("./vendor.def456.js");

    // Base64 encoded endpoint
    var decoded = atob("L2FwaS92Mi9vYnVzY2VkL3VzZXJz");
    fetch(decoded);

    // Hex encoded endpoint
    var hexPath = "\x2f\x61\x70\x69\x2f\x76\x32\x2f\x73\x65\x63\x72\x65\x74\x2d\x65\x6e\x64\x70\x6f\x69\x6e\x74";
    fetch(hexPath);

    // Unicode encoded endpoint
    var uniPath = "\u002f\u0061\u0070\u0069\u002f\u0076\u0032\u002f\u0075\u0073\u0065\u0072\u002d\u0070\u0072\u006f\u0066\u0069\u006c\u0065";
    fetch(uniPath);

    // String.fromCharCode
    var ccPath = String.fromCharCode(47,97,112,105,47,118,50,47,102,114,111,109,45,99,111,117,110,116);
    fetch(ccPath);

    // eval with hex
    eval("\x66\x65\x74\x63\x68\x28\x22\x2f\x61\x70\x69\x2f\x76\x32\x2f\x65\x76\x61\x6c\x2d\x65\x6e\x64\x70\x6f\x69\x6e\x74\x22\x29");

    // eval with base64
    eval(atob("ZmV0Y2goIi9hcGkvdjIvYmFzZTY0LWVuZHBvaW50Iik="));

    // Database connection string
    var DB_URL = "postgres://admin:password123@db.internal.com:5432/myapp";

    // Generic password
    var mail_config = { password: "smtp_secret_pass_123" };

    // Dangerous sinks for testing
    document.getElementById("out").innerHTML = userInput;
    setTimeout("doSomething()", 100);
    var url = "https://" + location.hash.substring(1);
    window.location.href = url;

    // Internal / private host references
    var devApi = "http://localhost:3000/api";
    var stage = "https://staging.testapp.local/admin";
    var backup = "https://192.168.1.50:8443/backup";
    var grafana = "http://grafana.internal.corp:3000/d/abc";

    // JWT samples for Phase 3 analyzer (fake keys only)
    // alg=none (unsigned) — CRITICAL
    var jwtNone = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.";
    // HS256 with weak secret "secret" — CRITICAL when cracked; kid path traversal
    var jwtWeak = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Ii4uLy4uL2V0Yy9wYXNzd2QifQ.eyJzdWIiOiJ1c2VyMSIsInJvbGUiOiJhZG1pbiIsImV4cCI6NDEwMjQ0NDgwMH0.37v4b22djkCt_PFJq-b2KgRj-bTLlT_X5vcxZ85rVPE";
    // RS256 missing exp — MEDIUM
    var jwtNoExp = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0Iiwic2NvcGUiOiJhZG1pbiB3cml0ZSJ9.c2lnbmF0dXJl";
    '''

@app.route("/static/chunk-abc123.js")
def chunk_js():
    return '''
    fetch("/api/v2/chunk-data");
    axios.get("/api/v2/analytics");
    '''

@app.route("/static/vendor.def456.js")
def vendor_js():
    return '''
    fetch("/api/v2/vendor-endpoint");
    '''

@app.route("/api/v2/<path:path>", methods=["GET", "POST", "OPTIONS"])
def api_catchall(path):
    # Intentionally vulnerable CORS for testing (reflects Origin + credentials)
    origin = request.headers.get("Origin")
    if origin:
        resp = jsonify({"status": "ok", "path": path})
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
        return resp
    return jsonify({"status": "ok", "path": path})


@app.route("/api/v1/public", methods=["GET", "OPTIONS"])
def api_public():
    # Wildcard CORS (medium severity)
    resp = jsonify({"status": "ok"})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/api/v2/null-cred", methods=["GET", "OPTIONS"])
def api_null_cred():
    # Null origin + credentials (critical) — sandboxed iframe attack
    resp = jsonify({"status": "ok", "path": "null-cred"})
    origin = request.headers.get("Origin")
    if origin == "null":
        resp.headers["Access-Control-Allow-Origin"] = "null"
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    elif request.method == "OPTIONS":
        # Preflight for non-null origins: no ACAO (not allowed)
        resp.status_code = 204
    return resp


@app.route("/api/v2/legit", methods=["GET", "OPTIONS"])
def api_legit():
    # Reflect only the exact legitimate origin (scheme + host + port) — INFO
    origin = request.headers.get("Origin")
    expected = request.url_root.rstrip("/")  # e.g. http://127.0.0.1:5555
    resp = jsonify({"status": "ok"})
    if origin and origin.rstrip("/") == expected:
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
    elif request.method == "OPTIONS":
        resp.status_code = 204
    return resp


@app.after_request
def add_cors(resp):
    # OPTIONS preflight shell only — do NOT inject ACAO (routes own CORS policy).
    # Generic reflection lives on /api/v2/<path> catch-all; wildcard on /api/v1/public.
    if request.method == "OPTIONS" and "Access-Control-Allow-Origin" not in resp.headers:
        resp.status_code = 204
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


if __name__ == "__main__":
    app.run(port=5555, debug=True)
