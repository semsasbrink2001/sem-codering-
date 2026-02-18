import os
import sqlite3
from functools import wraps
from pathlib import Path

from flask import Flask, g, redirect, render_template, request, session, url_for, flash
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "app.db"

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-change-me")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('user', 'admin')) DEFAULT 'user',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        """
    )

    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "admin123")

    cur = db.execute("SELECT id FROM users WHERE username = ?", (admin_username,))
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
            (admin_username, generate_password_hash(admin_password)),
        )
    db.commit()
    db.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Log eerst in om verder te gaan.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("user_id") is None:
            flash("Log eerst in om verder te gaan.", "error")
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            flash("Alleen beheerders hebben toegang tot deze pagina.", "error")
            return redirect(url_for("dashboard"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_current_user():
    return {
        "current_user": {
            "id": session.get("user_id"),
            "username": session.get("username"),
            "role": session.get("role"),
        }
    }


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if len(username) < 3:
            flash("Gebruikersnaam moet minstens 3 tekens hebben.", "error")
            return render_template("register.html")
        if len(password) < 6:
            flash("Wachtwoord moet minstens 6 tekens hebben.", "error")
            return render_template("register.html")

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'user')",
                (username, generate_password_hash(password)),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Gebruikersnaam bestaat al.", "error")
            return render_template("register.html")

        flash("Account aangemaakt. Je kunt nu inloggen.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT id, username, password_hash, role, active FROM users WHERE username = ?",
            (username,),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Onjuiste inloggegevens.", "error")
            return render_template("login.html")

        if user["active"] == 0:
            flash("Je account is gedeactiveerd. Neem contact op met de beheerder.", "error")
            return render_template("login.html")

        session.clear()
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]

        flash("Succesvol ingelogd.", "success")
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Je bent uitgelogd.", "success")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/admin")
@admin_required
def admin_panel():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, active, created_at FROM users ORDER BY created_at DESC"
    ).fetchall()
    return render_template("admin.html", users=users)


@app.route("/admin/users/create", methods=["POST"])
@admin_required
def admin_create_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")

    if role not in {"user", "admin"}:
        flash("Ongeldige rol.", "error")
        return redirect(url_for("admin_panel"))

    if len(username) < 3 or len(password) < 6:
        flash("Gebruikersnaam of wachtwoord is te kort.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
        flash("Gebruiker aangemaakt.", "success")
    except sqlite3.IntegrityError:
        flash("Gebruikersnaam bestaat al.", "error")

    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/update", methods=["POST"])
@admin_required
def admin_update_user(user_id: int):
    role = request.form.get("role", "user")
    active = 1 if request.form.get("active") == "on" else 0
    password = request.form.get("password", "")

    if role not in {"user", "admin"}:
        flash("Ongeldige rol.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("Gebruiker niet gevonden.", "error")
        return redirect(url_for("admin_panel"))

    if password.strip():
        db.execute(
            "UPDATE users SET role = ?, active = ?, password_hash = ? WHERE id = ?",
            (role, active, generate_password_hash(password), user_id),
        )
    else:
        db.execute(
            "UPDATE users SET role = ?, active = ? WHERE id = ?",
            (role, active, user_id),
        )

    db.commit()

    if session.get("user_id") == user_id:
        session["role"] = role

    flash(f"Gebruiker {user['username']} bijgewerkt.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id: int):
    if session.get("user_id") == user_id:
        flash("Je kunt je eigen account niet verwijderen.", "error")
        return redirect(url_for("admin_panel"))

    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash("Gebruiker verwijderd.", "success")
    return redirect(url_for("admin_panel"))


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
else:
    init_db()
