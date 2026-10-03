"""
Intentionally Vulnerable Training Laboratory for KRYPT CLI.
Contains controlled, isolated vulnerabilities for authorized testing and validation.
"""

from typing import Optional
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from starlette.routing import Route, Mount
import sqlite3

# Initialize in-memory mock laboratory database
def init_lab_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    cur = conn.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT, email TEXT)")
    cur.execute("INSERT INTO users VALUES (1, 'alice', 'alice123', 'user', 'alice@lab.local')")
    cur.execute("INSERT INTO users VALUES (2, 'bob', 'bob123', 'user', 'bob@lab.local')")
    cur.execute("INSERT INTO users VALUES (3, 'admin', 'admin_secret_9981', 'admin', 'admin@lab.local')")
    
    cur.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, category TEXT, price REAL)")
    cur.execute("INSERT INTO products VALUES (101, 'Security Key', 'hardware', 49.99)")
    cur.execute("INSERT INTO products VALUES (102, 'Encrypted USB', 'hardware', 29.99)")
    cur.execute("INSERT INTO products VALUES (103, 'Antivirus License', 'software', 89.99)")
    conn.commit()
    return conn

lab_conn = init_lab_db()


async def homepage(request):
    """Home page with navigation, forms, and assets."""
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>KRYPT Vulnerable Laboratory</title>
</head>
<body>
    <h1>KRYPT Intentionally Vulnerable Laboratory</h1>
    <p>Welcome to the authorized test environment for KRYPT CLI security verification.</p>
    <nav>
        <a href="/search?q=security">Search Catalog</a> |
        <a href="/login">User Login</a> |
        <a href="/profile?id=1">Profile (IDOR)</a> |
        <a href="/admin/dashboard">Admin Area</a> |
        <a href="/api/users">API Users</a> |
        <a href="/robots.txt">Robots</a>
    </nav>
    <form action="/search" method="GET">
        <label>Search:</label>
        <input type="text" name="q" value="" />
        <button type="submit">Submit</button>
    </form>
    <script src="/assets/app.js"></script>
</body>
</html>"""
    # Deliberately missing CSP, HSTS, X-Frame-Options
    response = HTMLResponse(html_content)
    response.headers["Server"] = "KRYPT-Lab/1.0 (Starlette/Uvicorn)"
    return response


async def search_endpoint(request):
    """Vulnerable to Reflected XSS and SQL Injection."""
    q = request.query_params.get("q", "")
    
    # 1. Intentionally vulnerable SQL query
    cur = lab_conn.cursor()
    db_results = []
    error_msg = ""
    if q:
        sql = f"SELECT id, name, category, price FROM products WHERE name = '{q}'"
        try:
            cur.execute(sql)
            db_results = cur.fetchall()
        except sqlite3.OperationalError as e:
            error_msg = f"sqlite3.OperationalError: {str(e)}"

    # 2. Intentionally unencoded reflection (XSS)
    html_content = f"""<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
    <h2>Search Results for: {q}</h2>
    {"<div class='error' style='color:red;'>Database Error: " + error_msg + "</div>" if error_msg else ""}
    <ul>
        {"".join(f"<li>{r[1]} ({r[2]}) - ${r[3]}</li>" for r in db_results)}
    </ul>
    <p><a href="/">Return Home</a></p>
</body>
</html>"""
    return HTMLResponse(html_content)


async def login_endpoint(request):
    """Vulnerable to SQL Injection & Insecure Cookies."""
    if request.method == "POST":
        import urllib.parse
        body_bytes = await request.body()
        parsed_body = urllib.parse.parse_qs(body_bytes.decode(errors="replace"))
        username = parsed_body.get("username", [""])[0] if "username" in parsed_body else request.query_params.get("username", "")
        password = parsed_body.get("password", [""])[0] if "password" in parsed_body else request.query_params.get("password", "")

        cur = lab_conn.cursor()
        sql = f"SELECT id, username, role FROM users WHERE username = '{username}' AND password = '{password}'"
        try:
            cur.execute(sql)
            user = cur.fetchone()
            if user:
                resp = HTMLResponse(f"<h3>Welcome {user[1]} (Role: {user[2]})</h3>")
                # Intentionally vulnerable session cookie: missing HttpOnly and Secure
                resp.headers.append("Set-Cookie", f"session_id=mock_session_alice_9821; Path=/")
                return resp
            else:
                return HTMLResponse("<h3>Invalid credentials</h3>", status_code=401)
        except sqlite3.OperationalError as e:
            return HTMLResponse(f"<h3>Database Error: sqlite3.OperationalError: {str(e)}</h3>", status_code=500)

    html_content = """<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h2>Laboratory Authentication</h2>
    <form action="/login" method="POST">
        <label>Username:</label><input type="text" name="username" /><br/>
        <label>Password:</label><input type="password" name="password" /><br/>
        <button type="submit">Sign In</button>
    </form>
</body>
</html>"""
    return HTMLResponse(html_content)


async def profile_endpoint(request):
    """Vulnerable to Insecure Direct Object Reference (IDOR)."""
    user_id = request.query_params.get("id", "1")
    cur = lab_conn.cursor()
    cur.execute("SELECT id, username, role, email FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if user:
        return JSONResponse({
            "id": user[0],
            "username": user[1],
            "role": user[2],
            "email": user[3],
            "note": "Confidential Account Data"
        })
    return JSONResponse({"error": "User not found"}, status_code=404)


async def admin_dashboard(request):
    """Vulnerable to Broken Access Control (Unrestricted Admin Endpoint)."""
    return HTMLResponse("""<!DOCTYPE html>
<html>
<head><title>Admin Dashboard</title></head>
<body>
    <h1>Admin Control Panel</h1>
    <p>Welcome Administrator. System telemetry: ACTIVE. Users: 3. DB: SQLite.</p>
    <div id="admin-actions">
        <a href="/admin/users">Manage User Accounts</a>
    </div>
</body>
</html>""")


async def admin_users(request):
    """Admin API with user data."""
    cur = lab_conn.cursor()
    cur.execute("SELECT id, username, role, email FROM users")
    users = [{"id": r[0], "username": r[1], "role": r[2], "email": r[3]} for r in cur.fetchall()]
    return JSONResponse({"admin_user_list": users})


async def api_users(request):
    """Public API list."""
    return JSONResponse([
        {"id": 1, "username": "alice"},
        {"id": 2, "username": "bob"}
    ])


async def assets_app_js(request):
    """JavaScript asset with endpoints."""
    js_content = """
// KRYPT Lab Application JavaScript
const API_BASE = "/api";
function fetchUserData(userId) {
    return fetch('/api/users/' + userId).then(r => r.json());
}
function loadAdminStats() {
    return fetch('/api/admin/stats').then(r => r.json());
}
console.log("KRYPT Lab App loaded");
"""
    return Response(js_content, media_type="application/javascript")


async def robots_txt(request):
    """Robots.txt file."""
    content = """User-agent: *
Disallow: /admin
Disallow: /debug
Sitemap: http://127.0.0.1:8888/sitemap.xml
"""
    return PlainTextResponse(content)


async def sitemap_xml(request):
    """Sitemap.xml file."""
    content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
   <url><loc>http://127.0.0.1:8888/</loc></url>
   <url><loc>http://127.0.0.1:8888/search</loc></url>
   <url><loc>http://127.0.0.1:8888/login</loc></url>
</urlset>"""
    return Response(content, media_type="application/xml")


async def env_exposure(request):
    """Exposed .env configuration file."""
    content = """APP_ENV=production
DB_PASSWORD=secret_database_root_password_2026
SECRET_KEY=krypt_jwt_master_secret_key_88192
DATABASE_URL=sqlite:///lab.db
"""
    return PlainTextResponse(content)


async def git_exposure(request):
    """Exposed .git/HEAD."""
    return PlainTextResponse("ref: refs/heads/main\n")


async def debug_vars(request):
    """Exposed debug endpoint."""
    return JSONResponse({
        "cmdline": ["python", "lab/server.py"],
        "memstats": {"Alloc": 1420184, "TotalAlloc": 5910240, "Sys": 12894104},
        "goroutines": 12
    })


routes = [
    Route("/", homepage),
    Route("/search", search_endpoint),
    Route("/login", login_endpoint, methods=["GET", "POST"]),
    Route("/profile", profile_endpoint),
    Route("/admin", admin_dashboard),
    Route("/admin/dashboard", admin_dashboard),
    Route("/admin/users", admin_users),
    Route("/api/users", api_users),
    Route("/assets/app.js", assets_app_js),
    Route("/robots.txt", robots_txt),
    Route("/sitemap.xml", sitemap_xml),
    Route("/.env", env_exposure),
    Route("/.git/HEAD", git_exposure),
    Route("/debug/vars", debug_vars),
]

import os
from lab.hardened import hardened_app

vulnerable_app = Starlette(debug=False, routes=routes)

class DualModeApp:
    """Dispatches requests to hardened or vulnerable app based on mode setting."""
    async def __call__(self, scope, receive, send):
        mode = os.environ.get("KRYPT_LAB_MODE", "vulnerable").lower()
        
        # Check for runtime header or query override if present
        if scope["type"] == "http":
            headers = dict(scope.get("headers", []))
            if b"x-security-mode" in headers:
                sec_header = headers[b"x-security-mode"].decode("latin1").lower()
                if "hardened" in sec_header:
                    mode = "hardened"
                elif "vulnerable" in sec_header:
                    mode = "vulnerable"
            qs = scope.get("query_string", b"").decode("latin1").lower()
            if "mode=hardened" in qs:
                mode = "hardened"

        if mode == "hardened":
            await hardened_app(scope, receive, send)
        else:
            await vulnerable_app(scope, receive, send)

app = DualModeApp()

