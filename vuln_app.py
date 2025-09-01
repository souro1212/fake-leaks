# vuln_app.py
# -----------------------------------------
# EDUCATIONAL PURPOSES ONLY — INTENTIONALLY INSECURE
# -----------------------------------------

from flask import Flask, request, jsonify, make_response
import sqlite3
import os
import subprocess
import platform
import base64
import pickle
import requests
import yaml  # pip install pyyaml
from urllib.parse import urlparse, unquote

app = Flask(__name__)

# ------------------------------------------------
# Set up a tiny in-memory DB with sample data
# ------------------------------------------------
def init_db():
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    c = conn.cursor()
    c.execute("CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    c.executemany(
        "INSERT INTO users(name, role) VALUES (?, ?)",
        [("alice", "admin"), ("bob", "user"), ("charlie", "user")],
    )
    conn.commit()
    return conn

DB = init_db()

@app.route("/")
def index():
    return make_response(
        """
        <h1>Intentionally Vulnerable Demo</h1>
        <ul>
          <li>/search?q=NAME — <b>SQL Injection</b> (string formatting)</li>
          <li>/echo?msg=TEXT — <b>Reflected XSS</b> (no encoding)</li>
          <li>/ping?host=HOST — <b>Command Injection</b> (shell=True)</li>
          <li>/read?path=PATH — <b>Path Traversal</b> (no normalization)</li>
          <li>/fetch?url=URL — <b>SSRF</b> (server-side request)</li>
          <li>POST /yaml (text/yaml) — <b>Unsafe yaml.load</b></li>
          <li>POST /pickle (base64 in body) — <b>Insecure pickle.loads</b></li>
        </ul>
        <p style="color:red">⚠️ DO NOT DEPLOY. For local training only.</p>
        """,
        200,
        {"Content-Type": "text/html"},
    )

# ------------------------------------------------
# VULN: SQL Injection (unsafe string formatting)
# e.g., /search?q=alice
# ------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # VULN: Directly formatting user input into SQL
    sql = f"SELECT id, name, role FROM users WHERE name LIKE '%{q}%'"
    try:
        rows = DB.cursor().execute(sql).fetchall()
        return jsonify({"query": sql, "results": rows})
    except Exception as e:
        return jsonify({"error": str(e), "query": sql}), 500

# ------------------------------------------------
# VULN: Reflected XSS (no output encoding)
# e.g., /echo?msg=Hello
# ------------------------------------------------
@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    # VULN: Injects user input directly into HTML
    return f"<h2>ECHO:</h2><div>{msg}</div>"

# ------------------------------------------------
# VULN: Command Injection (shell=True)
# e.g., /ping?host=127.0.0.1
# ------------------------------------------------
@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    flag = "-n" if platform.system().lower().startswith("win") else "-c"
    cmd = f"ping {flag} 1 {host}"
    # VULN: Passing unsanitized input to the shell
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        return make_response(f"<pre>{out.decode('utf-8', errors='ignore')}</pre>", 200)
    except subprocess.CalledProcessError as e:
        return make_response(f"<pre>{e.output.decode('utf-8', errors='ignore')}</pre>", 400)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ------------------------------------------------
# VULN: Path Traversal (naive join, no normalization)
# e.g., /read?path=notes.txt  (reads files/notes.txt)
# ------------------------------------------------
BASE_DIR = os.path.abspath("files")
os.makedirs(BASE_DIR, exist_ok=True)
with open(os.path.join(BASE_DIR, "notes.txt"), "w") as f:
    f.write("Sample note inside ./files/notes.txt\n")

@app.route("/read")
def read_file():
    rel_path = request.args.get("path", "notes.txt")
    # VULN: Using user-provided path directly
    target = os.path.join(BASE_DIR, rel_path)
    try:
        with open(target, "rb") as fh:
            data = fh.read()
        return make_response(f"<pre>{data.decode('utf-8', errors='ignore')}</pre>", 200)
    except Exception as e:
        return jsonify({"error": str(e), "target": target}), 400

# ------------------------------------------------
# VULN: SSRF (server fetches arbitrary URL)
# e.g., /fetch?url=http://127.0.0.1:5000/
# ------------------------------------------------
@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # VULN: No allowlist / no scheme checks beyond whatever requests supports
    try:
        r = requests.get(url, timeout=5, verify=False)
        return jsonify({
            "url": url,
            "status_code": r.status_code,
            "headers": dict(r.headers),
            "body": r.text[:2000]  # truncate
        })
    except Exception as e:
        return jsonify({"error": str(e), "url": url}), 400

# ------------------------------------------------
# VULN: Unsafe YAML deserialization (yaml.load)
# POST text/yaml to /yaml
# ------------------------------------------------
@app.route("/yaml", methods=["POST"])
def parse_yaml():
    data = request.get_data(as_text=True) or ""
    try:
        # VULN: yaml.load with default/unsafe loader can execute arbitrary objects
        obj = yaml.load(data, Loader=yaml.Loader)  # intentionally unsafe
        return jsonify({"parsed": obj})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ------------------------------------------------
# VULN: Insecure pickle deserialization
# POST base64-encoded pickle bytes to /pickle
# ------------------------------------------------
@app.route("/pickle", methods=["POST"])
def parse_pickle():
    try:
        raw = request.get_data() or b""
        b = base64.b64decode(raw)
        # VULN: pickle.loads executes arbitrary code on load
        obj = pickle.loads(b)
        return jsonify({"unpickled_type": type(obj).__name__, "repr": repr(obj)})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

# ------------------------------------------------
# Start server (debug=True is itself risky!)
# ------------------------------------------------
if __name__ == "__main__":
    # Bind only to localhost to reduce accidental exposure.
    app.run(host="127.0.0.1", port=5000, debug=True)

#test test
