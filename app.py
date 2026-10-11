
import os
import sqlite3
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_from_directory,
)
from werkzeug.security import generate_password_hash, check_password_hash


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Set it in ~/CTF_Box/.env"
    )

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = os.path.join(BASE_DIR, "ctf.db")
ARTIFACT_DIR = os.path.join(app.static_folder, "challenge-files")


# --------------------------------------------------
# DATABASE CONNECTION
# --------------------------------------------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


# --------------------------------------------------
# DATABASE INITIALIZATION
# Preserves existing users, scores, and solves.
# Seeds challenges only when the table is empty.
# --------------------------------------------------

def init_db():
    conn = get_db()

    try:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            score INTEGER DEFAULT 20
        );

        CREATE TABLE IF NOT EXISTS challenges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            category TEXT NOT NULL,
            description TEXT NOT NULL,
            points INTEGER NOT NULL,
            flag TEXT NOT NULL,
            file_link TEXT,
            unlock_after INTEGER DEFAULT NULL,
            hint TEXT,
            hint_cost INTEGER DEFAULT 20
        );

        CREATE TABLE IF NOT EXISTS solves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            UNIQUE(user_id, challenge_id)
        );

        CREATE TABLE IF NOT EXISTS hints_used (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            challenge_id INTEGER NOT NULL,
            UNIQUE(user_id, challenge_id)
        );
        """)

        existing = conn.execute(
            "SELECT COUNT(*) AS c FROM challenges"
        ).fetchone()["c"]

        if existing == 0:
            stages = [
                (
                    "CV-01 :: Hidden Message",
                    "Steganography",
                    "An ordinary company image was recovered from an employee workstation. IT believes it conceals more than it shows. Inspect it closely.",
                    100,
                    "CV{metadata_never_forgets_4576}",
                    "/static/challenge-files/nexacore_office.jpg",
                    None,
                    "Check the file's metadata for hidden text. Tools like strings or exiftool can reveal it.",
                    20,
                ),
                (
                    "CV-02 :: Network Trail",
                    "Networking",
                    "A clue from Stage 1 points to a suspicious system inside the NexaCore internal network. Scan it. Something is listening.",
                    100,
                    "CV{network_recon_success}",
                    None,
                    1,
                    "Try connecting with FTP. Anonymous login might be allowed.",
                    20,
                ),
                (
                    "CV-03 :: Web Gateway",
                    "Web Security",
                    "Network reconnaissance surfaced a web service with a designed weakness. Breach the front door.",
                    150,
                    "CV{web_gateway_sqli_bypass_success}",
                    None,
                    2,
                    "The login form may not be sanitizing input. What happens if you comment out the rest of the SQL query?",
                    30,
                ),
                (
                    "CV-04 :: Encrypted Note",
                    "Cryptography",
                    "Behind the gateway sits an encrypted note, left deliberately by the intruder. Break the cipher.",
                    150,
                    "CV{cl4ss1c_c1ph3rs_st1ll_m4tt3r}",
                    "/static/challenge-files/encrypted_note.txt",
                    3,
                    "It's a classical polyalphabetic cipher. The keyword relates to the company name mentioned throughout the scenario.",
                    30,
                ),
                (
                    "CV-05 :: Deleted Evidence",
                    "Digital Forensics",
                    "The decrypted note reveals an attempt to erase the trail. Nothing is ever truly gone.",
                    200,
                    "CV{d3l3t3d_but_n0t_g0n3}",
                    "/static/challenge-files/cv05_evidence.img",
                    4,
                    "Deleting a file doesn't erase its data from disk. Try searching the raw image for readable strings.",
                    40,
                ),
                (
                    "CV-06 :: Final Server",
                    "Linux/System Security",
                    "The trail ends at one Linux server. Breach it, escalate, and close the case.",
                    250,
                    "CV{final_server_suid_python_root_shell}",
                    None,
                    5,
                    "Look for binaries with the SUID bit set. Some can be abused to spawn a root shell.",
                    50,
                ),
            ]

            conn.executemany(
                """
                INSERT INTO challenges (
                    title, category, description, points,
                    flag, file_link, unlock_after, hint, hint_cost
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                stages,
            )

            conn.commit()

    finally:
        conn.close()


# --------------------------------------------------
# LOGIN REQUIRED DECORATOR
# --------------------------------------------------

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


# --------------------------------------------------
# REGISTER
# --------------------------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            existing = conn.execute(
                "SELECT id FROM users WHERE username = ?",
                (username,),
            ).fetchone()

            if existing:
                flash("That username is already taken.")
                return redirect(url_for("register"))

            password_hash = generate_password_hash(password)

            conn.execute(
                """
                INSERT INTO users (username, password_hash, score)
                VALUES (?, ?, 20)
                """,
                (username, password_hash),
            )
            conn.commit()

        except sqlite3.IntegrityError:
            flash("That username is already taken.")
            return redirect(url_for("register"))

        finally:
            conn.close()

        flash("Access created. You may connect now.")
        return redirect(url_for("login"))

    return render_template("register.html")


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()

        try:
            user = conn.execute(
                "SELECT * FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        finally:
            conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("challenges"))

        flash("Access denied. Invalid credentials.")
        return redirect(url_for("login"))

    return render_template("login.html")


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------
# CHALLENGE DASHBOARD
# --------------------------------------------------

@app.route("/")
@login_required
def challenges():
    conn = get_db()

    try:
        all_challs = conn.execute(
            "SELECT * FROM challenges ORDER BY id ASC"
        ).fetchall()

        solved_ids = {
            row["challenge_id"]
            for row in conn.execute(
                "SELECT challenge_id FROM solves WHERE user_id = ?",
                (session["user_id"],),
            ).fetchall()
        }

        hints_used_ids = {
            row["challenge_id"]
            for row in conn.execute(
                "SELECT challenge_id FROM hints_used WHERE user_id = ?",
                (session["user_id"],),
            ).fetchall()
        }

    finally:
        conn.close()

    visible_challs = []

    for chal in all_challs:
        prereq = chal["unlock_after"]

        if prereq is None or prereq in solved_ids:
            visible_challs.append(chal)

    return render_template(
        "challenges.html",
        challenges=visible_challs,
        solved_ids=solved_ids,
        hints_used_ids=hints_used_ids,
        total_stages=len(all_challs),
    )


# --------------------------------------------------
# SUBMIT FLAG
# --------------------------------------------------

@app.route("/submit/<int:challenge_id>", methods=["POST"])
@login_required
def submit_flag(challenge_id):
    submitted_flag = request.form.get("flag", "").strip()
    conn = get_db()

    try:
        chal = conn.execute(
            "SELECT * FROM challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()

        if not chal:
            flash("Challenge not found.")
            return redirect(url_for("challenges"))

        if chal["unlock_after"] is not None:
            prereq_solved = conn.execute(
                """
                SELECT id FROM solves
                WHERE user_id = ? AND challenge_id = ?
                """,
                (session["user_id"], chal["unlock_after"]),
            ).fetchone()

            if not prereq_solved:
                flash(
                    "Access denied. Complete the previous stage first."
                )
                return redirect(url_for("challenges"))

        already_solved = conn.execute(
            """
            SELECT id FROM solves
            WHERE user_id = ? AND challenge_id = ?
            """,
            (session["user_id"], challenge_id),
        ).fetchone()

        if already_solved:
            flash("Stage already cleared.")

        elif submitted_flag == chal["flag"]:
            conn.execute(
                """
                INSERT INTO solves (user_id, challenge_id)
                VALUES (?, ?)
                """,
                (session["user_id"], challenge_id),
            )

            conn.execute(
                "UPDATE users SET score = score + ? WHERE id = ?",
                (chal["points"], session["user_id"]),
            )

            conn.commit()

            flash(
                f"Access granted. +{chal['points']} points. "
                "Next stage decrypted."
            )

        else:
            flash("Incorrect flag. Access denied.")

    finally:
        conn.close()

    return redirect(url_for("challenges"))


# --------------------------------------------------
# USE HINT
# --------------------------------------------------

@app.route("/hint/<int:challenge_id>", methods=["POST"])
@login_required
def use_hint(challenge_id):
    conn = get_db()

    try:
        chal = conn.execute(
            "SELECT * FROM challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()

        if not chal:
            flash("Challenge not found.")
            return redirect(url_for("challenges"))

        if not chal["hint"]:
            flash("No hint available for this challenge.")
            return redirect(url_for("challenges"))

        if chal["unlock_after"] is not None:
            prereq_solved = conn.execute(
                """
                SELECT id FROM solves
                WHERE user_id = ? AND challenge_id = ?
                """,
                (session["user_id"], chal["unlock_after"]),
            ).fetchone()

            if not prereq_solved:
                flash(
                    "Access denied. Complete the previous stage first."
                )
                return redirect(url_for("challenges"))

        already_used = conn.execute(
            """
            SELECT id FROM hints_used
            WHERE user_id = ? AND challenge_id = ?
            """,
            (session["user_id"], challenge_id),
        ).fetchone()

        if already_used:
            flash(f"Hint: {chal['hint']}")
            return redirect(url_for("challenges"))

        user = conn.execute(
            "SELECT score FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

        if user is None:
            session.clear()
            flash("Your session is invalid. Please log in again.")
            return redirect(url_for("login"))

        if user["score"] < chal["hint_cost"]:
            flash(
                f"Not enough points for this hint. "
                f"You need {chal['hint_cost']}, "
                f"you have {user['score']}."
            )
            return redirect(url_for("challenges"))

        conn.execute(
            """
            INSERT INTO hints_used (user_id, challenge_id)
            VALUES (?, ?)
            """,
            (session["user_id"], challenge_id),
        )

        conn.execute(
            "UPDATE users SET score = score - ? WHERE id = ?",
            (chal["hint_cost"], session["user_id"]),
        )

        conn.commit()

        flash(f"Hint: {chal['hint']} (-{chal['hint_cost']} points)")

    finally:
        conn.close()

    return redirect(url_for("challenges"))


# --------------------------------------------------
# SCOREBOARD
# --------------------------------------------------

@app.route("/scoreboard")
@login_required
def scoreboard():
    conn = get_db()

    try:
        users = conn.execute(
            "SELECT username, score FROM users ORDER BY score DESC"
        ).fetchall()
    finally:
        conn.close()

    return render_template("scoreboard.html", users=users)


# --------------------------------------------------
# DOWNLOAD CHALLENGE ARTIFACT
# --------------------------------------------------

@app.route("/download/<int:challenge_id>")
@login_required
def download_artifact(challenge_id):
    conn = get_db()

    try:
        chal = conn.execute(
            "SELECT * FROM challenges WHERE id = ?",
            (challenge_id,),
        ).fetchone()

        if not chal:
            flash("Challenge not found.")
            return redirect(url_for("challenges"))

        if not chal["file_link"]:
            flash("No artifact is available for this challenge.")
            return redirect(url_for("challenges"))

        if chal["unlock_after"] is not None:
            solved = conn.execute(
                """
                SELECT id FROM solves
                WHERE user_id = ? AND challenge_id = ?
                """,
                (session["user_id"], chal["unlock_after"]),
            ).fetchone()

            if not solved:
                flash("Complete the previous stage first.")
                return redirect(url_for("challenges"))

        filename = os.path.basename(chal["file_link"])

    finally:
        conn.close()

    return send_from_directory(
        ARTIFACT_DIR,
        filename,
        as_attachment=True,
    )


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(
        debug=False,
        host="0.0.0.0",
        port=8080,
    )
