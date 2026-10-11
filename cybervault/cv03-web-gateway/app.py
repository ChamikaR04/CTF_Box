"""
CyberVault - CV-03 Web Gateway
------------------------------
Intentionally vulnerable Flask app for a controlled CTF environment.
Vulnerability: SQL Injection in the login form (string-built query),
allowing authentication bypass to reach the protected /dashboard page
that reveals the flag.

FOR USE ONLY INSIDE THE ISOLATED CTF NETWORK.
"""

import sqlite3
import os
from flask import Flask, request, session, redirect, url_for, render_template_string

app = Flask(__name__)
app.secret_key = "cv03-dev-secret-change-me"  # fine for an isolated lab box
DB_PATH = "/app/data/nexacore.db"

FLAG = "CV{web_gateway_sqli_bypass_success}"

LOGIN_PAGE = """
<h2>NexaCore Employee Portal</h2>
<form method="POST" action="/login">
  Username: <input name="username"><br>
  Password: <input name="password" type="password"><br>
  <input type="submit" value="Login">
</form>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
"""

DASHBOARD_PAGE = """
<h2>Welcome, {{ user }}</h2>
<p>Internal Notice: Unusual login activity detected on Stage 2 server.</p>
<p><b>FLAG: {{ flag }}</b></p>
<a href="/logout">Logout</a>
"""


def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        username TEXT,
                        password TEXT)""")
    # Seed a couple of "employee" accounts. Real password isn't needed to solve.
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO users (username, password) VALUES (?, ?)",
                         [("jsmith", "Winter2025!"), ("admin", "N3xaC0re#Adm1n")])
    conn.commit()
    conn.close()


@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # --- INTENTIONALLY VULNERABLE QUERY (do not "fix" this) ---
        # String-built SQL allows classic auth-bypass payloads, e.g.
        # username: admin' --
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.OperationalError:
            row = None
        conn.close()

        if row:
            session["user"] = row[1]
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."

    return render_template_string(LOGIN_PAGE, error=error)


@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))
    return render_template_string(DASHBOARD_PAGE, user=session["user"], flag=FLAG)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
