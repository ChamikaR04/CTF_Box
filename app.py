from flask import Flask, render_template, request, redirect, url_for, session, flash, send_from_directory
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "change-this-secret-key-later"
DB_PATH = os.path.join(os.path.dirname(__file__), "ctf.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        score INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        description TEXT NOT NULL,
        points INTEGER NOT NULL,
        flag TEXT NOT NULL,
        file_link TEXT,
        unlock_after INTEGER DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS solves (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        challenge_id INTEGER NOT NULL,
        UNIQUE(user_id, challenge_id)
    );
    """)
    conn.commit()

    # Matches Section 5 of the CyberVault report exactly: CV-01 through CV-06,
    # same domains, same order, same dependency chain (Section 3.6 gameplay flow).
    existing = conn.execute("SELECT COUNT(*) AS c FROM challenges").fetchone()["c"]
    if existing == 0:
        stages = [
            ("CV-01 :: Hidden Message", "Steganography",
             "An ordinary company image was recovered from an employee workstation. IT believes it conceals more than it shows. Inspect it closely.",
             100, "CV{Cs_Nexacore}", "/static/challenge-files/cv01-image.jpg", None, 0),
            ("CV-02 :: Network Trail", "Networking",
             "A clue from Stage 1 points to a suspicious system inside the NexaCore internal network. Scan it. Something is listening.",
             100, "CV{network_recon_success}", None, 1),
            ("CV-03 :: Web Gateway", "Web Security",
             "Network reconnaissance surfaced a web service with a designed weakness. Breach the front door.",
             150, "CV{sql_injection_bypass}", None, 2),
            ("CV-04 :: Encrypted Note", "Cryptography",
             "Behind the gateway sits an encrypted note, left deliberately by the intruder. Break the cipher.",
             150, "CV{vigenere_cipher_solved}", "/static/challenge-files/cv04-encrypted-note.txt", 3),
            ("CV-05 :: Deleted Evidence", "Digital Forensics",
             "The decrypted note reveals an attempt to erase the trail. Nothing is ever truly gone.",
             200, "CV{deleted_files_never_really_disappear}", "/static/challenge-files/cv05-evidence-package.zip", 4),
            ("CV-06 :: Final Server", "Linux/System Security",
             "The trail ends at one Linux server. Breach it, escalate, and close the case.",
             250, "CV{privilege_escalation_complete}", None, 5),
        ]
        for s in stages:
            conn.execute(
                "INSERT INTO challenges (title, category, description, points, flag, file_link, unlock_after) VALUES (?, ?, ?, ?, ?, ?, ?)",
                s
            )
        conn.commit()
    conn.close()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        conn = get_db()
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
        if existing:
            flash("That username is already taken.")
            conn.close()
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, password_hash))
        conn.commit()
        conn.close()
        flash("Access created. You may connect now.")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("challenges"))
        else:
            flash("Access denied. Invalid credentials.")
            return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


def login_required(func):
    from functools import wraps
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


@app.route("/")
@login_required
def challenges():
    conn = get_db()
    all_challs = conn.execute("SELECT * FROM challenges ORDER BY id ASC").fetchall()
    solved_ids = {
        row["challenge_id"] for row in
        conn.execute("SELECT challenge_id FROM solves WHERE user_id = ?", (session["user_id"],)).fetchall()
    }
    conn.close()

    visible_challs = []
    for chal in all_challs:
        prereq = chal["unlock_after"]
        if prereq is None or prereq in solved_ids:
            visible_challs.append(chal)

    return render_template("challenges.html", challenges=visible_challs, solved_ids=solved_ids,
                            total_stages=len(all_challs))


@app.route("/submit/<int:challenge_id>", methods=["POST"])
@login_required
def submit_flag(challenge_id):
    submitted_flag = request.form["flag"].strip()
    conn = get_db()
    chal = conn.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()

    if not chal:
        flash("Challenge not found.")
        conn.close()
        return redirect(url_for("challenges"))

    if chal["unlock_after"] is not None:
        prereq_solved = conn.execute(
            "SELECT * FROM solves WHERE user_id = ? AND challenge_id = ?",
            (session["user_id"], chal["unlock_after"])
        ).fetchone()
        if not prereq_solved:
            flash("Access denied. Complete the previous stage first.")
            conn.close()
            return redirect(url_for("challenges"))

    already_solved = conn.execute(
        "SELECT * FROM solves WHERE user_id = ? AND challenge_id = ?",
        (session["user_id"], challenge_id)
    ).fetchone()

    if already_solved:
        flash("Stage already cleared.")
    elif submitted_flag == chal["flag"]:
        conn.execute("INSERT INTO solves (user_id, challenge_id) VALUES (?, ?)", (session["user_id"], challenge_id))
        conn.execute("UPDATE users SET score = score + ? WHERE id = ?", (chal["points"], session["user_id"]))
        conn.commit()
        flash(f"Access granted. +{chal['points']} points. Next stage decrypted.")
    else:
        flash("Incorrect flag. Access denied.")

    conn.close()
    return redirect(url_for("challenges"))


@app.route("/scoreboard")
@login_required
def scoreboard():
    conn = get_db()
    users = conn.execute("SELECT username, score FROM users ORDER BY score DESC").fetchall()
    conn.close()
    return render_template("scoreboard.html", users=users)


@app.route("/download/<int:challenge_id>")
@login_required
def download_artifact(challenge_id):
    conn = get_db()
    chal = conn.execute(
        "SELECT * FROM challenges WHERE id = ?",
        (challenge_id,)
    ).fetchone()
    conn.close()

    if not chal:
        flash("Challenge not found.")
        return redirect(url_for("challenges"))

    # Check whether the challenge has an artifact
    if not chal["file_link"]:
        flash("No artifact is available for this challenge.")
        return redirect(url_for("challenges"))

    # Make sure the player has unlocked this challenge
    if chal["unlock_after"] is not None:
        conn = get_db()
        solved = conn.execute(
            "SELECT * FROM solves WHERE user_id = ? AND challenge_id = ?",
            (session["user_id"], chal["unlock_after"])
        ).fetchone()
        conn.close()

        if not solved:
            flash("Complete the previous stage first.")
            return redirect(url_for("challenges"))

    # Get the file path from the URL
    filename = chal["file_link"].split("/")[-1]

    return send_from_directory(
        os.path.join(app.static_folder, "challenge-files"),
        filename,
        as_attachment=True
    )

if __name__ == "__main__":
    init_db()
    app.run(debug=True, host="0.0.0.0", port=5000)
