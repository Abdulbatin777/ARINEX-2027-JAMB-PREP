import csv
import io
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import click
from flask import (
    Flask, abort, flash, g, jsonify, redirect, render_template,
    request, session, url_for
)
from flask.cli import with_appcontext
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from config import Config

BASE_DIR = Path(__file__).resolve().parent

app = Flask(__name__)
app.config.from_object(Config)
csrf = CSRFProtect(app)

# -------------------------------------------------------------------
# DATABASE
# -------------------------------------------------------------------

def get_db():
    if "db" not in g:
        db_path = Path(app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)

        g.db = sqlite3.connect(str(db_path), timeout=20)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 20000")

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    schema_path = BASE_DIR / "schema.sql"

    with schema_path.open("r", encoding="utf-8") as file:
        db.executescript(file.read())

    subjects = [
        "Use of English", "Mathematics", "Physics", "Chemistry",
        "Biology", "Agricultural Science", "Arabic", "Christian Religious Studies", "Commerce", "Computer Studies",
        "Economics", "French", "Geography", "Government", "Hausa",
        "History", "Home Economics", "Igbo", "Islamic Studies",
        "Literature in English", "Physical and Health Education", "Yoruba"
    ]

    for name in subjects:
        db.execute(
            "INSERT OR IGNORE INTO subjects(name, is_utme) VALUES (?, 1)",
            (name,)
        )

    db.commit()


@app.before_request
def prepare_request():
    g.user = None
    user_id = session.get("user_id")

    if user_id:
        g.user = get_db().execute(
            "SELECT * FROM users WHERE id = ? AND is_active = 1",
            (user_id,)
        ).fetchone()

        if g.user is None:
            session.clear()


@app.context_processor
def inject_globals():
    unread = 0

    if g.get("user"):
        unread = get_db().execute(
            """SELECT COUNT(*) AS n FROM notifications
               WHERE is_read = 0 AND (user_id = ? OR user_id IS NULL)""",
            (g.user["id"],)
        ).fetchone()["n"]

    return {
        "current_user": g.get("user"),
        "unread_notifications": unread,
        "premium_price": app.config["PREMIUM_PRICE"],
    }


# -------------------------------------------------------------------
# AUTHORIZATION
# -------------------------------------------------------------------

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.user:
            return redirect(url_for("login"))

        if not g.user["is_admin"]:
            abort(403)

        return view(*args, **kwargs)

    return wrapped


def has_access(user_id, section):
    row = get_db().execute(
        "SELECT * FROM section_access WHERE user_id = ?",
        (user_id,)
    ).fetchone()

    return bool(row and row[section])


def notify(user_id, title, message):
    db = get_db()
    db.execute(
        """INSERT INTO notifications(user_id, title, message)
           VALUES (?, ?, ?)""",
        (user_id, title, message)
    )
    db.commit()


def notify_admins(title, message):
    db = get_db()
    admins = db.execute(
        "SELECT id FROM users WHERE is_admin = 1 AND is_active = 1"
    ).fetchall()

    for admin in admins:
        notify(admin["id"], title, message)


def parse_datetime(value):
    return datetime.fromisoformat(value)


def now_utc():
    return datetime.now(timezone.utc)


# -------------------------------------------------------------------
# CLI: CREATE THE FIRST ADMINISTRATOR
# -------------------------------------------------------------------

@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.option("--whatsapp", prompt="WhatsApp number")
@click.password_option()
def create_admin(username, whatsapp, password):
    """Create an administrator account."""
    init_db()

    username = username.strip()
    whatsapp = whatsapp.strip()

    if not username or not whatsapp:
        raise click.ClickException("Username and WhatsApp are required.")

    db = get_db()

    try:
        cursor = db.execute(
            """INSERT INTO users
               (username, whatsapp, password_hash, is_admin)
               VALUES (?, ?, ?, 1)""",
            (username, whatsapp, generate_password_hash(password))
        )

        db.execute(
            "INSERT INTO section_access(user_id) VALUES (?)",
            (cursor.lastrowid,)
        )

        db.commit()
        click.echo("Administrator created successfully.")

    except sqlite3.IntegrityError:
        db.rollback()
        raise click.ClickException(
            "That username or WhatsApp number already exists."
        )


# -------------------------------------------------------------------
# HOME, REGISTRATION AND LOGIN
# -------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("home.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        whatsapp = request.form.get("whatsapp", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        accepted = request.form.get("agree_rules")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,30}", username):
            flash("Use 3–30 letters, numbers or underscores.", "error")

        elif not re.fullmatch(r"\+?[0-9]{10,15}", whatsapp):
            flash("Enter a valid WhatsApp number.", "error")

        elif len(password) < 10:
            flash("Your password must contain at least 10 characters.", "error")

        elif password != confirm:
            flash("Passwords do not match.", "error")

        elif not accepted:
            flash("Please accept the website rules.", "error")

        else:
            db = get_db()

            try:
                cursor = db.execute(
                    """INSERT INTO users
                       (username, whatsapp, password_hash)
                       VALUES (?, ?, ?)""",
                    (
                        username,
                        whatsapp,
                        generate_password_hash(password)
                    )
                )

                user_id = cursor.lastrowid

                # All paid sections start locked.
                db.execute(
                    "INSERT INTO section_access(user_id) VALUES (?)",
                    (user_id,)
                )

                db.commit()

                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))

            except sqlite3.IntegrityError:
                db.rollback()
                flash("That username or WhatsApp number is already registered.",
                      "error")

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_db().execute(
            """SELECT * FROM users
               WHERE username = ? COLLATE NOCASE""",
            (username,)
        ).fetchone()

        if (
            user
            and user["is_active"]
            and check_password_hash(user["password_hash"], password)
        ):
            session.clear()
            session["user_id"] = user["id"]
            session.permanent = True

            flash("Welcome back!", "success")

            if user["is_admin"]:
                return redirect(url_for("admin_dashboard"))

            return redirect(url_for("dashboard"))

        flash("Invalid login details or inactive account.", "error")

    return render_template("login.html")

@app.route("/forgot-password")
def forgot_password():
    return render_template("forgot_password.html")
@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have logged out.", "success")
    return redirect(url_for("home"))


# -------------------------------------------------------------------
# STUDENT DASHBOARD
# -------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = g.user["id"]

    attempts = db.execute(
        """SELECT * FROM attempts
           WHERE user_id = ? AND status = 'submitted'
           ORDER BY submitted_at DESC LIMIT 10""",
        (uid,)
    ).fetchall()

    total_attempts = db.execute(
        """SELECT COUNT(*) AS n FROM attempts
           WHERE user_id = ? AND status = 'submitted'""",
        (uid,)
    ).fetchone()["n"]

    best = db.execute(
        """SELECT MAX(score * 100.0 / total_questions) AS best
           FROM attempts
           WHERE user_id = ? AND status = 'submitted'
             AND total_questions > 0""",
        (uid,)
    ).fetchone()["best"]

    # Best percentage for each exam type.
    practice_best = db.execute(
        """SELECT MAX(score * 100.0 / total_questions) AS best
           FROM attempts
           WHERE user_id = ? AND status = 'submitted'
             AND LOWER(exam_type) = 'practice'
             AND total_questions > 0""",
        (uid,)
    ).fetchone()["best"]

    mock_best = db.execute(
        """SELECT MAX(score * 100.0 / total_questions) AS best
           FROM attempts
           WHERE user_id = ? AND status = 'submitted'
             AND LOWER(exam_type) IN ('mock', 'mock_exam', 'mock exam')
             AND total_questions > 0""",
        (uid,)
    ).fetchone()["best"]

    # Scaled best scores out of 400.
    practice_scaled = round(practice_best * 4) if practice_best is not None else None
    mock_scaled = round(mock_best * 4) if mock_best is not None else None

    access = db.execute(
        "SELECT * FROM section_access WHERE user_id = ?", (uid,)
    ).fetchone()

    subjects = db.execute(
        "SELECT * FROM subjects WHERE is_active = 1 ORDER BY name"
    ).fetchall()

    today = now_utc().date().isoformat()

    today_row = db.execute(
        """SELECT questions_answered FROM daily_activity
           WHERE user_id = ? AND activity_date = ?""",
        (uid, today)
    ).fetchone()

    activity_dates = [
        row["activity_date"]
        for row in db.execute(
            """SELECT activity_date FROM daily_activity
               WHERE user_id = ? ORDER BY activity_date DESC""",
            (uid,)
        ).fetchall()
    ]

    streak = 0
    check_date = now_utc().date()
    date_set = set(activity_dates)

    if check_date.isoformat() not in date_set:
        check_date -= timedelta(days=1)

    while check_date.isoformat() in date_set:
        streak += 1
        check_date -= timedelta(days=1)

    return render_template(
        "dashboard.html",
        attempts=attempts,
        total_attempts=total_attempts,
        best_score=round(best or 0, 1),
        practice_best=round(practice_best, 1) if practice_best is not None else None,
        mock_best=round(mock_best, 1) if mock_best is not None else None,
        practice_scaled=practice_scaled,
        mock_scaled=mock_scaled,
        access=access,
        subjects=subjects,
        today_questions=today_row["questions_answered"] if today_row else 0,
        streak=streak
    )



# -------------------------------------------------------------------
# PRACTICE
# -------------------------------------------------------------------

@app.route("/practice", methods=["GET", "POST"])
@login_required
def practice():
    db = get_db()
    uid = g.user["id"]

    free_attempts = db.execute(
        """SELECT COUNT(*) AS n FROM attempts
           WHERE user_id = ? AND exam_type = 'practice'""",
        (uid,)
    ).fetchone()["n"]

    practice_unlocked = has_access(uid, "practice")
    can_practise = practice_unlocked or (
        free_attempts < app.config["FREE_PRACTICE_ATTEMPTS"]
    )

    if not can_practise:
        flash("Practice is locked. Contact the administrator.", "warning")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        subject_id = request.form.get("subject_id", type=int)
        count = request.form.get(
            "question_count",
            app.config["DEFAULT_PRACTICE_QUESTIONS"],
            type=int
        )
        minutes = request.form.get(
            "duration",
            app.config["DEFAULT_PRACTICE_MINUTES"],
            type=int
        )

        subject = db.execute(
            "SELECT id FROM subjects WHERE id = ? AND is_active = 1",
            (subject_id,)
        ).fetchone()

        if not subject:
            flash("Select a valid subject.", "error")
            return redirect(url_for("practice"))

        if not 1 <= count <= app.config["MAX_PRACTICE_QUESTIONS"]:
            flash("Question count must be between 1 and 180.", "error")
            return redirect(url_for("practice"))

        if not 1 <= minutes <= 180:
            flash("Duration must be between 1 and 180 minutes.", "error")
            return redirect(url_for("practice"))

        available = db.execute(
            """SELECT id FROM questions
               WHERE subject_id = ? AND is_published = 1
               ORDER BY RANDOM() LIMIT ?""",
            (subject_id, count)
        ).fetchall()

        if len(available) < count:
            flash(
                f"Only {len(available)} published questions are available. "
                "Add more questions or reduce the question count.",
                "error"
            )
            return redirect(url_for("practice"))

        question_ids = [row["id"] for row in available]
        start = now_utc()
        deadline = start + timedelta(minutes=minutes)

        cursor = db.execute(
            """INSERT INTO attempts
               (user_id, exam_type, subject_ids, question_ids,
                started_at, deadline, total_questions)
               VALUES (?, 'practice', ?, ?, ?, ?, ?)""",
            (
                uid,
                json.dumps([subject_id]),
                json.dumps(question_ids),
                start.isoformat(),
                deadline.isoformat(),
                len(question_ids)
            )
        )

        attempt_id = cursor.lastrowid

        db.executemany(
            """INSERT INTO attempt_answers(attempt_id, question_id)
               VALUES (?, ?)""",
            [(attempt_id, qid) for qid in question_ids]
        )

        db.commit()
        return redirect(url_for("take_exam", attempt_id=attempt_id))

    subjects = db.execute(
        "SELECT * FROM subjects WHERE is_active = 1 ORDER BY name"
    ).fetchall()

    return render_template(
        "practice.html",
        subjects=subjects,
        free_attempts_used=free_attempts,
        free_attempts_remaining=max(
            0, app.config["FREE_PRACTICE_ATTEMPTS"] - free_attempts
        ),
        practice_unlocked=practice_unlocked,
        default_question_count=app.config["DEFAULT_PRACTICE_QUESTIONS"],
        default_duration=app.config["DEFAULT_PRACTICE_MINUTES"]
    )


# -------------------------------------------------------------------
# MOCK EXAM SETUP
# -------------------------------------------------------------------

@app.route("/mock", methods=["GET", "POST"])
@login_required
def mock_setup():
    db = get_db()
    uid = g.user["id"]

    if not has_access(uid, "mock_exam"):
        flash("Mock Exam is locked. Request access from the administrator.",
              "warning")
        return redirect(url_for("dashboard"))

    subjects = db.execute(
        """SELECT * FROM subjects
           WHERE is_active = 1 AND is_utme = 1
           ORDER BY name"""
    ).fetchall()

    english = db.execute(
        """SELECT id FROM subjects
           WHERE name = 'Use of English' AND is_active = 1"""
    ).fetchone()

    if not english:
        flash("Use of English is missing from the subject catalogue.", "error")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        selected = request.form.getlist("subject_ids", type=int)

        if english["id"] in selected:
            selected.remove(english["id"])

        selected = list(dict.fromkeys(selected))

        if len(selected) != 3:
            flash("Choose exactly three subjects besides Use of English.",
                  "error")
            return redirect(url_for("mock_setup"))

        if english["id"] in selected:
            abort(400)

        all_subject_ids = [english["id"]] + selected

        question_ids = []

        for subject_id in all_subject_ids:
            subject = db.execute(
                "SELECT id FROM subjects WHERE id = ? AND is_utme = 1 AND is_active = 1",
                (subject_id,)
            ).fetchone()

            if not subject:
                flash("Invalid subject selection.", "error")
                return redirect(url_for("mock_setup"))

            required = (
                app.config["ENGLISH_QUESTION_COUNT"]
                if subject_id == english["id"]
                else app.config["OTHER_SUBJECT_QUESTION_COUNT"]
            )

            questions = db.execute(
                """SELECT id FROM questions
                   WHERE subject_id = ? AND is_published = 1
                   ORDER BY RANDOM() LIMIT ?""",
                (subject_id, required)
            ).fetchall()

            if len(questions) < required:
                subject_name = db.execute(
                    "SELECT name FROM subjects WHERE id = ?",
                    (subject_id,)
                ).fetchone()["name"]

                flash(
                    f"{subject_name} has only {len(questions)} published "
                    f"questions; {required} are required. Please upload "
                    "enough questions before starting the mock exam.",
                    "error"
                )
                return redirect(url_for("mock_setup"))

            question_ids.extend(row["id"] for row in questions)

        # Mix questions from all four subjects.
        import random
        random.shuffle(question_ids)

        start = now_utc()
        deadline = start + timedelta(
            minutes=app.config["MOCK_DURATION_MINUTES"]
        )

        cursor = db.execute(
            """INSERT INTO attempts
               (user_id, exam_type, subject_ids, question_ids,
                started_at, deadline, total_questions)
               VALUES (?, 'mock', ?, ?, ?, ?, ?)""",
            (
                uid,
                json.dumps(all_subject_ids),
                json.dumps(question_ids),
                start.isoformat(),
                deadline.isoformat(),
                len(question_ids)
            )
        )

        attempt_id = cursor.lastrowid

        db.executemany(
            """INSERT INTO attempt_answers(attempt_id, question_id)
               VALUES (?, ?)""",
            [(attempt_id, qid) for qid in question_ids]
        )

        db.commit()
        return redirect(url_for("take_exam", attempt_id=attempt_id))

    return render_template("mock_setup.html", subjects=subjects)


# -------------------------------------------------------------------
# EXAM ENGINE
# -------------------------------------------------------------------

def get_owned_attempt(attempt_id):
    attempt = get_db().execute(
        "SELECT * FROM attempts WHERE id = ? AND user_id = ?",
        (attempt_id, g.user["id"])
    ).fetchone()

    if not attempt:
        abort(404)

    return attempt


def submit_attempt(attempt_id):
    db = get_db()

    attempt = db.execute(
        "SELECT * FROM attempts WHERE id = ?", (attempt_id,)
    ).fetchone()

    if not attempt or attempt["status"] != "in_progress":
        return

    deadline = parse_datetime(attempt["deadline"])

    # The server decides when an exam expires.
    if now_utc() < deadline:
        # Manual submission is allowed.
        pass

    answers = db.execute(
        """SELECT aa.question_id, aa.selected_answer, q.correct_answer
           FROM attempt_answers aa
           JOIN questions q ON q.id = aa.question_id
           WHERE aa.attempt_id = ?""",
        (attempt_id,)
    ).fetchall()

    score = 0

    for answer in answers:
        correct = int(
            answer["selected_answer"] is not None
            and answer["selected_answer"] == answer["correct_answer"]
        )

        score += correct

        db.execute(
            """UPDATE attempt_answers SET is_correct = ?
               WHERE attempt_id = ? AND question_id = ?""",
            (correct, attempt_id, answer["question_id"])
        )

    db.execute(
        """UPDATE attempts
           SET score = ?, submitted_at = ?, status = 'submitted'
           WHERE id = ? AND status = 'in_progress'""",
        (score, now_utc().isoformat(), attempt_id)
    )

    answered_count = db.execute(
        "SELECT COUNT(*) AS n FROM attempt_answers WHERE attempt_id = ? AND selected_answer IS NOT NULL",
        (attempt_id,)
    ).fetchone()["n"]
    activity_date = now_utc().date().isoformat()
    db.execute(
        """INSERT INTO daily_activity(user_id, activity_date, questions_answered)
           VALUES (?, ?, ?)
           ON CONFLICT(user_id, activity_date) DO UPDATE SET
             questions_answered = questions_answered + excluded.questions_answered""",
        (attempt["user_id"], activity_date, answered_count)
    )
    db.commit()


@app.route("/exam/<int:attempt_id>", methods=["GET", "POST"])
@login_required
def take_exam(attempt_id):
    db = get_db()
    attempt = get_owned_attempt(attempt_id)

    if attempt["status"] == "submitted":
        return redirect(url_for("exam_result", attempt_id=attempt_id))

    deadline = parse_datetime(attempt["deadline"])

    if now_utc() >= deadline:
        submit_attempt(attempt_id)
        flash("Your examination time has ended.", "info")
        return redirect(url_for("exam_result", attempt_id=attempt_id))

    if request.method == "POST":
        # Saving answers is permitted only before the server deadline.
        action = request.form.get("action", "save")

        question_id = request.form.get("question_id", type=int)
        answer = request.form.get("answer", "").upper()

        if question_id and "answer" in request.form:
            if answer and answer not in ("A", "B", "C", "D"):
                abort(400)

            owned_question = db.execute(
                """SELECT id FROM attempt_answers
                   WHERE attempt_id = ? AND question_id = ?""",
                (attempt_id, question_id)
            ).fetchone()

            if not owned_question:
                abort(400)

            db.execute(
                """UPDATE attempt_answers
                   SET selected_answer = ?
                   WHERE attempt_id = ? AND question_id = ?""",
                (answer or None, attempt_id, question_id)
            )
            db.commit()

        if action == "submit":
            submit_attempt(attempt_id)
            return redirect(url_for("exam_result", attempt_id=attempt_id))

        return redirect(url_for(
            "take_exam",
            attempt_id=attempt_id,
            q=request.form.get("go_to_q", request.form.get("next_q", request.form.get("q", "0")))
        ))

    question_rows = db.execute(
        """SELECT q.*, s.name AS subject_name,
                  aa.selected_answer, aa.is_correct
           FROM attempt_answers aa
           JOIN questions q ON q.id = aa.question_id
           JOIN subjects s ON s.id = q.subject_id
           WHERE aa.attempt_id = ?
           ORDER BY aa.id""",
        (attempt_id,)
    ).fetchall()

    questions = [dict(row) for row in question_rows]

    # Never expose the answer key before the examination is submitted.
    for question in questions:
        question.pop("correct_answer", None)
        question.pop("explanation", None)

    remaining = max(0, int((deadline - now_utc()).total_seconds()))

    return render_template(
        "exam.html",
        attempt=attempt,
        questions=questions,
        remaining_seconds=remaining,
        current_question=request.args.get("q", default=0, type=int)
    )



@app.route("/exam/<int:attempt_id>/result")
@login_required
def exam_result(attempt_id):
    attempt = get_owned_attempt(attempt_id)

    if attempt["status"] != "submitted":
        return redirect(url_for("take_exam", attempt_id=attempt_id))

    db = get_db()

    details = db.execute(
        """SELECT q.*, s.name AS subject_name,
                  aa.selected_answer, aa.is_correct
           FROM attempt_answers aa
           JOIN questions q ON q.id = aa.question_id
           JOIN subjects s ON s.id = q.subject_id
           WHERE aa.attempt_id = ?
           ORDER BY aa.id""",
        (attempt_id,)
    ).fetchall()

    total_questions = attempt["total_questions"] or 0
    score = attempt["score"] or 0

    percentage = round(
        score * 100 / total_questions, 2
    ) if total_questions else 0

    scaled_score = round(
        score * 400 / total_questions
    ) if total_questions else 0

    correct_count = sum(
        1 for q in details if q["is_correct"] == 1
    )

    answered_count = sum(
        1 for q in details if q["selected_answer"] is not None
    )

    incorrect_count = answered_count - correct_count
    unanswered_count = max(0, total_questions - answered_count)

    return render_template(
        "result.html",
        attempt=attempt,
        details=details,
        percentage=percentage,
        scaled_score=scaled_score,
        correct_count=correct_count,
        incorrect_count=incorrect_count,
        unanswered_count=unanswered_count,
        total_questions=total_questions
    )



@app.route("/results")
@login_required
def results():
    rows = get_db().execute(
        """SELECT * FROM attempts
           WHERE user_id = ? AND status = 'submitted'
           ORDER BY submitted_at DESC""",
        (g.user["id"],)
    ).fetchall()

    return render_template("results.html", results=rows)


# -------------------------------------------------------------------
# BOOKMARKS AND WRONG-ANSWER REVISION
# -------------------------------------------------------------------

@app.route("/bookmarks")
@login_required
def bookmarks():
    rows = get_db().execute(
        """SELECT q.*, s.name AS subject_name
           FROM bookmarks b
           JOIN questions q ON q.id = b.question_id
           JOIN subjects s ON s.id = q.subject_id
           WHERE b.user_id = ? ORDER BY b.created_at DESC""",
        (g.user["id"],)
    ).fetchall()

    return render_template("bookmarks.html", questions=rows)


@app.route("/bookmark/<int:question_id>", methods=["POST"])
@login_required
def toggle_bookmark(question_id):
    db = get_db()

    question = db.execute(
        "SELECT id FROM questions WHERE id = ? AND is_published = 1",
        (question_id,)
    ).fetchone()

    if not question:
        abort(404)

    existing = db.execute(
        """SELECT 1 FROM bookmarks
           WHERE user_id = ? AND question_id = ?""",
        (g.user["id"], question_id)
    ).fetchone()

    if existing:
        db.execute(
            "DELETE FROM bookmarks WHERE user_id = ? AND question_id = ?",
            (g.user["id"], question_id)
        )
        flash("Bookmark removed.", "success")
    else:
        db.execute(
            "INSERT INTO bookmarks(user_id, question_id) VALUES (?, ?)",
            (g.user["id"], question_id)
        )
        flash("Question bookmarked.", "success")

    db.commit()
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/revision")
@login_required
def revision():
    rows = get_db().execute(
        """SELECT DISTINCT q.*, s.name AS subject_name
           FROM attempt_answers aa
           JOIN attempts a ON a.id = aa.attempt_id
           JOIN questions q ON q.id = aa.question_id
           JOIN subjects s ON s.id = q.subject_id
           WHERE a.user_id = ? AND a.status = 'submitted'
             AND aa.is_correct = 0
           ORDER BY q.subject_id, q.id""",
        (g.user["id"],)
    ).fetchall()

    return render_template("revision.html", questions=rows)


# -------------------------------------------------------------------
# ANALYTICS AND DAILY ACTIVITY
# -------------------------------------------------------------------

@app.route("/analytics")
@login_required
def analytics():
    db = get_db()
    uid = g.user["id"]

    subject_scores = db.execute(
        """SELECT s.name,
                  SUM(CASE WHEN aa.is_correct = 1 THEN 1 ELSE 0 END) AS correct,
                  COUNT(*) AS total
           FROM attempts a
           JOIN attempt_answers aa ON aa.attempt_id = a.id
           JOIN questions q ON q.id = aa.question_id
           JOIN subjects s ON s.id = q.subject_id
           WHERE a.user_id = ? AND a.status = 'submitted'
           GROUP BY s.id
           ORDER BY s.name""",
        (uid,)
    ).fetchall()

    # Best percentage and scaled score for Practice and Mock Exam.
    practice = db.execute(
        """SELECT
               MAX(score * 100.0 / total_questions) AS best_percentage,
               AVG(score * 100.0 / total_questions) AS average_percentage,
               COUNT(*) AS attempts
           FROM attempts
           WHERE user_id = ? AND status = 'submitted'
             AND LOWER(exam_type) = 'practice'
             AND total_questions > 0""",
        (uid,)
    ).fetchone()

    mock = db.execute(
        """SELECT
               MAX(score * 100.0 / total_questions) AS best_percentage,
               AVG(score * 100.0 / total_questions) AS average_percentage,
               COUNT(*) AS attempts
           FROM attempts
           WHERE user_id = ? AND status = 'submitted'
             AND LOWER(exam_type) IN ('mock', 'mock_exam', 'mock exam')
             AND total_questions > 0""",
        (uid,)
    ).fetchone()

    activity = db.execute(
        """SELECT * FROM daily_activity
           WHERE user_id = ?
           ORDER BY activity_date DESC LIMIT 30""",
        (uid,)
    ).fetchall()

    def prepare_stats(row):
        best = row["best_percentage"]
        average = row["average_percentage"]

        return {
            "best_percentage": round(best, 1) if best is not None else None,
            "best_scaled": round(best * 4) if best is not None else None,
            "average_percentage": round(average, 1) if average is not None else None,
            "average_scaled": round(average * 4) if average is not None else None,
            "attempts": row["attempts"] or 0
        }

    return render_template(
        "analytics.html",
        subject_scores=subject_scores,
        activity=activity,
        practice_stats=prepare_stats(practice),
        mock_stats=prepare_stats(mock)
    )




# -------------------------------------------------------------------
# LEADERBOARD: PERSONAL BEST AND IMPROVEMENT (NO PHONE NUMBERS SHOWN)
# -------------------------------------------------------------------

@app.route("/leaderboard")
@login_required
def leaderboard():
    rows = get_db().execute(
        """SELECT u.id, u.username, a.score, a.total_questions, a.submitted_at
           FROM users u JOIN attempts a ON a.user_id = u.id
           WHERE u.is_admin = 0 AND u.is_active = 1 AND a.status = 'submitted'
           ORDER BY u.id, a.submitted_at"""
    ).fetchall()
    grouped = {}
    for row in rows:
        percentage = (row["score"] or 0) * 100.0 / row["total_questions"] if row["total_questions"] else 0
        grouped.setdefault(row["id"], {"username": row["username"], "scores": []})["scores"].append(percentage)
    best_rows = []
    improvement_rows = []
    for data in grouped.values():
        scores = data["scores"]
        best_rows.append({"username": data["username"], "best": round(max(scores), 1), "attempts": len(scores)})
        first_average = sum(scores[:3]) / len(scores[:3])
        last_average = sum(scores[-3:]) / len(scores[-3:])
        improvement_rows.append({"username": data["username"], "improvement": round(last_average - first_average, 1), "attempts": len(scores)})
    best_rows.sort(key=lambda item: item["best"], reverse=True)
    improvement_rows.sort(key=lambda item: item["improvement"], reverse=True)
    return render_template("leaderboard.html", best_rows=best_rows[:20], improvement_rows=improvement_rows[:20])


# -------------------------------------------------------------------
# CLASSES
# -------------------------------------------------------------------

@app.route("/classes")
@login_required
def classes():
    if not has_access(g.user["id"], "classes"):
        flash("Classes are locked. Complete Premium payment and await approval.",
              "warning")
        return redirect(url_for("dashboard"))

    lessons = get_db().execute(
        """SELECT l.*, s.name AS subject_name
           FROM lessons l
           JOIN subjects s ON s.id = l.subject_id
           WHERE l.is_published = 1
           ORDER BY s.name, l.title"""
    ).fetchall()

    return render_template("classes.html", lessons=lessons)


@app.route("/lesson/<int:lesson_id>")
@login_required
def lesson(lesson_id):
    if not has_access(g.user["id"], "classes"):
        abort(403)

    row = get_db().execute(
        "SELECT * FROM lessons WHERE id = ? AND is_published = 1",
        (lesson_id,)
    ).fetchone()

    if not row:
        abort(404)

    return render_template("lesson.html", lesson=row)


# -------------------------------------------------------------------
# PREMIUM PAYMENTS
# -------------------------------------------------------------------

@app.route("/payments", methods=["GET", "POST"])
@login_required
def payments():
    db = get_db()
    uid = g.user["id"]

    if request.method == "POST":
        # The student submits a payment claim, not proof of payment.
        receipt_note = request.form.get("receipt_note", "").strip()

        if len(receipt_note) > 1000:
            flash("Payment reference is too long.", "error")
            return redirect(url_for("payments"))

        pending = db.execute(
            """SELECT id FROM payments
               WHERE user_id = ? AND status = 'pending'""",
            (uid,)
        ).fetchone()

        if pending:
            flash("You already have a pending payment submission.", "warning")
            return redirect(url_for("payments"))

        reference = secrets.token_hex(12).upper()

        db.execute(
            """INSERT INTO payments
               (user_id, amount, reference, receipt_note)
               VALUES (?, ?, ?, ?)""",
            (
                uid,
                app.config["PREMIUM_PRICE"],
                reference,
                receipt_note
            )
        )
        db.commit()

        notify_admins(
            "New Premium payment claim",
            f"Student {g.user['username']} submitted a payment claim "
            f"for ₦{app.config['PREMIUM_PRICE']}. Reference: {reference}. "
            "Verify the actual transfer before approving."
        )

        notify(
            uid,
            "Payment submission received",
            "Your payment claim is pending administrator verification."
        )

        flash("Payment submitted for review.", "success")
        return redirect(url_for("payments"))

    history = db.execute(
        """SELECT * FROM payments
           WHERE user_id = ? ORDER BY submitted_at DESC""",
        (uid,)
    ).fetchall()

    return render_template(
        "payments.html",
        payments=history,
        payment_bank=app.config["PAYMENT_BANK"],
        account_number=app.config["PAYMENT_ACCOUNT_NUMBER"],
        account_name=app.config["PAYMENT_ACCOUNT_NAME"],
        price=app.config["PREMIUM_PRICE"]
    )


@app.route("/notifications")
@login_required
def notifications():
    db = get_db()
    uid = g.user["id"]

    rows = db.execute(
        """SELECT * FROM notifications
           WHERE user_id = ? OR user_id IS NULL
           ORDER BY created_at DESC LIMIT 100""",
        (uid,)
    ).fetchall()

    db.execute(
        """UPDATE notifications SET is_read = 1
           WHERE user_id = ? OR user_id IS NULL""",
        (uid,)
    )
    db.commit()

    return render_template("notifications.html", notifications=rows)


# -------------------------------------------------------------------
# ADMIN DASHBOARD
# -------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_dashboard():
    db = get_db()

    stats = {
        "students": db.execute(
            "SELECT COUNT(*) AS n FROM users WHERE is_admin = 0"
        ).fetchone()["n"],
        "questions": db.execute(
            "SELECT COUNT(*) AS n FROM questions"
        ).fetchone()["n"],
        "published_questions": db.execute(
            "SELECT COUNT(*) AS n FROM questions WHERE is_published = 1"
        ).fetchone()["n"],
        "pending_payments": db.execute(
            "SELECT COUNT(*) AS n FROM payments WHERE status = 'pending'"
        ).fetchone()["n"],
        "lessons": db.execute(
            "SELECT COUNT(*) AS n FROM lessons"
        ).fetchone()["n"],
    }

    return render_template("admin/dashboard.html", stats=stats)


@app.route("/admin/students")
@admin_required
def admin_students():
    students = get_db().execute(
        """SELECT u.*, sa.practice, sa.classes, sa.mock_exam
           FROM users u
           LEFT JOIN section_access sa ON sa.user_id = u.id
           WHERE u.is_admin = 0 ORDER BY u.created_at DESC"""
    ).fetchall()

    return render_template("admin/students.html", students=students)

@app.route("/admin/students/<int:user_id>/reset-password", methods=["GET", "POST"])
@admin_required
def admin_reset_student_password(user_id):
    student = get_db().execute(
        "SELECT id, username FROM users WHERE id = ? AND is_admin = 0",
        (user_id,)
    ).fetchone()

    if student is None:
        abort(404)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm_password:
            flash("Passwords do not match.", "error")
        else:
            db = get_db()
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(password), user_id)
            )
            db.commit()

            flash(
                f"Password reset successfully for {student['username']}.",
                "success"
            )
            return redirect(url_for("admin_students"))

    return render_template("admin/reset_password.html", student=student)



@app.route("/admin/locks", methods=["GET", "POST"])
@admin_required
def admin_locks():
    db = get_db()
    user_id = request.values.get("user_id", type=int)

    students = db.execute(
        "SELECT id, username, whatsapp FROM users WHERE is_admin = 0"
    ).fetchall()

    if request.method == "POST":
        user_id = request.form.get("user_id", type=int)

        student = db.execute(
            "SELECT id FROM users WHERE id = ? AND is_admin = 0",
            (user_id,)
        ).fetchone()

        if not student:
            abort(404)

        # All three controls are independent.
        practice = int(request.form.get("practice") == "on")
        classes_access = int(request.form.get("classes") == "on")
        mock_exam = int(request.form.get("mock_exam") == "on")

        db.execute(
            """INSERT INTO section_access
               (user_id, practice, classes, mock_exam)
               VALUES (?, ?, ?, ?)
               ON CONFLICT(user_id) DO UPDATE SET
                 practice = excluded.practice,
                 classes = excluded.classes,
                 mock_exam = excluded.mock_exam""",
            (user_id, practice, classes_access, mock_exam)
        )
        db.commit()

        notify(
            user_id,
            "Your access settings changed",
            "The administrator has updated your section permissions."
        )

        flash("Student access settings saved.", "success")
        return redirect(url_for("admin_locks", user_id=user_id))

    selected = None

    if user_id:
        selected = db.execute(
            """SELECT u.id, u.username, sa.practice, sa.classes, sa.mock_exam
               FROM users u JOIN section_access sa ON sa.user_id = u.id
               WHERE u.id = ? AND u.is_admin = 0""",
            (user_id,)
        ).fetchone()

    return render_template(
        "admin/locks.html",
        students=students,
        selected=selected
    )


# -------------------------------------------------------------------
# ADMIN PAYMENT APPROVAL
# -------------------------------------------------------------------

@app.route("/admin/payments")
@admin_required
def admin_payments():
    rows = get_db().execute(
        """SELECT p.*, u.username, u.whatsapp
           FROM payments p JOIN users u ON u.id = p.user_id
           ORDER BY p.submitted_at DESC"""
    ).fetchall()

    return render_template("admin/payments.html", payments=rows)


@app.route("/admin/payments/<int:payment_id>/<action>", methods=["POST"])
@admin_required
def review_payment(payment_id, action):
    if action not in ("approve", "reject"):
        abort(404)

    db = get_db()

    payment = db.execute(
        "SELECT * FROM payments WHERE id = ?", (payment_id,)
    ).fetchone()

    if not payment:
        abort(404)

    if payment["status"] != "pending":
        flash("This payment has already been reviewed.", "warning")
        return redirect(url_for("admin_payments"))

    user_id = payment["user_id"]

    if action == "approve":
        db.execute(
            """UPDATE payments SET status = 'approved',
               reviewed_at = ?, reviewed_by = ? WHERE id = ?""",
            (now_utc().isoformat(), g.user["id"], payment_id)
        )

        # APPROVAL UNLOCKS PRACTICE, CLASSES, AND MOCK EXAM.
        db.execute(
            """INSERT INTO section_access(user_id, practice, classes, mock_exam)
               VALUES (?, 1, 1, 1)
               ON CONFLICT(user_id) DO UPDATE SET
                 practice = 1, classes = 1, mock_exam = 1""",
            (user_id,)
        )

        notify(
            user_id,
            "Premium payment approved",
            "Your payment has been approved. Practice, Classes, and Mock Exam are now unlocked."
        )

        message = "Payment approved. Practice, Classes, and Mock Exam unlocked."

    else:
        db.execute(
            """UPDATE payments SET status = 'rejected',
               reviewed_at = ?, reviewed_by = ? WHERE id = ?""",
            (now_utc().isoformat(), g.user["id"], payment_id)
        )

        notify(
            user_id,
            "Payment not approved",
            "Your payment submission was rejected. Please contact the "
            "administrator if you believe this is an error."
        )

        message = "Payment rejected."

    db.commit()
    flash(message, "success")
    return redirect(url_for("admin_payments"))


# -------------------------------------------------------------------
# ADMIN QUESTION MANAGEMENT
# -------------------------------------------------------------------

@app.route("/admin/questions")
@admin_required
def admin_questions():
    db = get_db()
    search = request.args.get("search", "").strip()
    subject_id = request.args.get("subject_id", type=int)

    sql = """SELECT q.*, s.name AS subject_name
             FROM questions q JOIN subjects s ON s.id = q.subject_id
             WHERE 1 = 1"""
    params = []

    if search:
        sql += " AND q.question_text LIKE ?"
        params.append(f"%{search}%")

    if subject_id:
        sql += " AND q.subject_id = ?"
        params.append(subject_id)

    sql += " ORDER BY q.id DESC"

    questions = db.execute(sql, params).fetchall()
    subjects = db.execute(
        "SELECT * FROM subjects ORDER BY name"
    ).fetchall()

    return render_template(
        "admin/questions.html",
        questions=questions,
        subjects=subjects,
        search=search,
        subject_id=subject_id
    )
@app.route(
    "/admin/questions/<int:question_id>/toggle-publish",
    methods=["POST"]
)
@admin_required
def admin_toggle_question_publish(question_id):
    db = get_db()

    question = db.execute(
        """SELECT id, is_published, question_text,
                  option_a, option_b, option_c, option_d,
                  correct_answer
           FROM questions
           WHERE id = ?""",
        (question_id,)
    ).fetchone()

    if not question:
        return jsonify({
            "ok": False,
            "message": "Question not found."
        }), 404

    currently_published = bool(question["is_published"])

    if not currently_published:
        required_fields = [
            question["question_text"],
            question["option_a"],
            question["option_b"],
            question["option_c"],
            question["option_d"]
        ]

        correct_answer = (
            question["correct_answer"] or ""
        ).strip().upper()

        if (
            any(not str(value or "").strip()
                for value in required_fields)
            or correct_answer not in ("A", "B", "C", "D")
        ):
            return jsonify({
                "ok": False,
                "message": (
                    "Complete the question, all four options, "
                    "and correct answer before publishing."
                )
            }), 400

    new_status = 0 if currently_published else 1

    db.execute(
        "UPDATE questions SET is_published = ? WHERE id = ?",
        (new_status, question_id)
    )
    db.commit()

    return jsonify({
        "ok": True,
        "is_published": bool(new_status),
        "message": (
            "Question published."
            if new_status
            else "Question unpublished."
        )
    })
@app.route("/admin/questions/publish-all", methods=["POST"])
@admin_required
def admin_publish_all_questions():
    db = get_db()
    subject_id = request.form.get("subject_id", type=int)

    if not subject_id:
        flash("Please select a subject.", "error")
        return redirect(url_for("admin_questions"))

    subject = db.execute(
        "SELECT id, name FROM subjects WHERE id = ?",
        (subject_id,),
    ).fetchone()

    if not subject:
        flash("Invalid subject selected.", "error")
        return redirect(url_for("admin_questions"))

    try:
        result = db.execute(
            """
            UPDATE questions
            SET is_published = 1
            WHERE subject_id = ?
              AND is_published = 0
              AND TRIM(COALESCE(question_text, '')) != ''
              AND TRIM(COALESCE(option_a, '')) != ''
              AND TRIM(COALESCE(option_b, '')) != ''
              AND TRIM(COALESCE(option_c, '')) != ''
              AND TRIM(COALESCE(option_d, '')) != ''
              AND UPPER(TRIM(COALESCE(correct_answer, '')))
                  IN ('A', 'B', 'C', 'D')
            """,
            (subject_id,),
        )

        published = result.rowcount
        db.commit()

        flash(
            f"Published {published} valid questions for "
            f"{subject['name']}.",
            "success",
        )

    except Exception:
        db.rollback()
        app.logger.exception("Bulk question publishing failed")
        flash("Publishing failed. Please try again.", "error")

    return redirect(url_for("admin_questions"))



@app.route("/admin/questions/add", methods=["GET", "POST"])
@admin_required
def admin_add_question():
    db = get_db()
    subjects = db.execute(
        "SELECT * FROM subjects WHERE is_active = 1 ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        subject_id = request.form.get("subject_id", type=int)
        topic_id = request.form.get("topic_id", type=int) or None
        text = request.form.get("question_text", "").strip()
        options = [
            request.form.get(f"option_{letter.lower()}", "").strip()
            for letter in "ABCD"
        ]
        correct = request.form.get("correct_answer", "").upper()
        explanation = request.form.get("explanation", "").strip()
        year = request.form.get("exam_year", type=int)
        source = request.form.get("source", "").strip()
        published = int(request.form.get("is_published") == "on")

        subject = db.execute(
            "SELECT id FROM subjects WHERE id = ?",
            (subject_id,)
        ).fetchone()

        if (
            not subject
            or not text
            or any(not option for option in options)
            or correct not in ("A", "B", "C", "D")
        ):
            flash("Complete the question and all four answer options.", "error")
            return render_template(
                "admin/question_form.html",
                subjects=subjects,
                question=None
            )

        if topic_id:
            topic = db.execute(
                "SELECT id FROM topics WHERE id = ? AND subject_id = ?",
                (topic_id, subject_id)
            ).fetchone()

            if not topic:
                flash("Choose a topic belonging to the selected subject.",
                      "error")
                return render_template(
                    "admin/question_form.html",
                    subjects=subjects,
                    question=None
                )

        db.execute(
            """INSERT INTO questions
               (subject_id, topic_id, question_text,
                option_a, option_b, option_c, option_d,
                correct_answer, explanation, exam_year, source,
                is_published)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                subject_id, topic_id, text,
                options[0], options[1], options[2], options[3],
                correct, explanation, year, source, published
            )
        )
        db.commit()

        flash("Question saved.", "success")
        return redirect(url_for("admin_questions"))

    return render_template(
        "admin/question_form.html",
        subjects=subjects,
        question=None
    )


@app.route("/admin/questions/<int:question_id>/delete", methods=["POST"])
@admin_required
def admin_delete_question(question_id):
    db = get_db()

    question = db.execute(
        "SELECT id FROM questions WHERE id = ?", (question_id,)
    ).fetchone()

    if not question:
        abort(404)

    used = db.execute(
        "SELECT 1 FROM attempt_answers WHERE question_id = ? LIMIT 1",
        (question_id,)
    ).fetchone()

    if used:
        # Preserve historical examination records.
        db.execute(
            "UPDATE questions SET is_published = 0 WHERE id = ?",
            (question_id,)
        )
        flash("Question unpublished to preserve exam history.", "success")
    else:
        db.execute(
            "DELETE FROM questions WHERE id = ?", (question_id,)
        )
        flash("Question deleted.", "success")

    db.commit()
    return redirect(url_for("admin_questions"))


# -------------------------------------------------------------------
# CSV QUESTION IMPORT
# -------------------------------------------------------------------

@app.route("/admin/questions/import", methods=["GET", "POST"])
@admin_required
def admin_import_questions():
    db = get_db()
    subjects = db.execute(
        "SELECT * FROM subjects ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        uploaded = request.files.get("file")
        subject_id = request.form.get("subject_id", type=int)

        if not uploaded or not uploaded.filename:
            flash("Select a CSV file.", "error")
            return redirect(url_for("admin_import_questions"))

        if not uploaded.filename.lower().endswith(".csv"):
            flash("Only CSV files are supported here.", "error")
            return redirect(url_for("admin_import_questions"))

        if not db.execute(
            "SELECT id FROM subjects WHERE id = ?", (subject_id,)
        ).fetchone():
            flash("Choose a valid subject.", "error")
            return redirect(url_for("admin_import_questions"))


        try:
            content = uploaded.stream.read().decode("utf-8-sig")
            print("CSV FILENAME:", uploaded.filename)
            print("CSV CONTENT LENGTH:", len(content))
            print("CSV FIRST 300 CHARACTERS:", repr(content[:300]))

            
            reader = csv.DictReader(io.StringIO(content, newline=""))

            # Normalize CSV headings so uppercase letters and spaces
            # do not prevent the import from working.
            if reader.fieldnames:
                reader.fieldnames = [
                    (name or "").strip().lstrip("\ufeff").lower()
                    for name in reader.fieldnames
                ]

            # Accept both question-bank and ARINEX CSV headings.
            aliases = {
                "question": "question_text",
                "question_text": "question_text",
                "option_a": "option_a",
                "option_b": "option_b",
                "option_c": "option_c",
                "option_d": "option_d",
                "correct_answer": "correct_answer",
                "explanation": "explanation",
                "exam_year": "exam_year",
                "topic": "topic",
                "source": "source",
            }

            if not reader.fieldnames:
                raise ValueError("The CSV file has no headings.")

            reader.fieldnames = [
                aliases.get(name, name) for name in reader.fieldnames
            ]

            required = {
                "question_text",
                "option_a",
                "option_b",
                "option_c",
                "option_d",
                "correct_answer",
            }

            if not required.issubset(set(reader.fieldnames)):
                found = ", ".join(reader.fieldnames)
                raise ValueError(
                    "CSV headings are missing or incorrect. "
                    f"Headings detected: {found}"
                )
            
            added = 0

            for row in reader:
                text = (row.get("question_text") or "").strip()
                options = [
                    (row.get(f"option_{letter}") or "").strip()
                    for letter in "abcd"
                ]
                answer = (
                    row.get("correct_answer") or ""
                ).strip().upper()

                if (
                    not text
                    or any(not option for option in options)
                    or answer not in ("A", "B", "C", "D")
                ):
                    continue

                topic_id = None
                topic_name = (row.get("topic") or "").strip()

                if topic_name:
                    db.execute(
                        """INSERT OR IGNORE INTO topics
                           (subject_id, name) VALUES (?, ?)""",
                        (subject_id, topic_name),
                    )

                    topic = db.execute(
                        """SELECT id FROM topics
                           WHERE subject_id = ? AND name = ?""",
                        (subject_id, topic_name),
                    ).fetchone()

                    topic_id = topic["id"] if topic else None

                year_text = (row.get("exam_year") or "").strip()
                year = int(year_text) if year_text.isdigit() else None

                db.execute(
                    """INSERT INTO questions
                       (subject_id, topic_id, question_text,
                        option_a, option_b, option_c, option_d,
                        correct_answer, explanation, exam_year, source,
                        is_published)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)""",
                    (
                        subject_id,
                        topic_id,
                        text,
                        options[0],
                        options[1],
                        options[2],
                        options[3],
                        answer,
                        (row.get("explanation") or "").strip(),
                        year,
                        (row.get("source") or "").strip(),
                    ),
                )
                added += 1

            db.commit()
            flash(
                f"Imported {added} valid questions as unpublished. "
                "Review them before publishing.",
                "success",
            )

        except (UnicodeDecodeError, csv.Error, ValueError) as exc:
            db.rollback()
            flash(f"Import failed: {exc}", "error")

        return redirect(url_for("admin_questions"))

    return render_template(
        "admin/import_questions.html",
        subjects=subjects,
    )





# -------------------------------------------------------------------
# ADMIN LESSON MANAGEMENT
# -------------------------------------------------------------------

@app.route("/admin/lessons", methods=["GET", "POST"])
@admin_required
def admin_lessons():
    db = get_db()
    subjects = db.execute(
        "SELECT * FROM subjects ORDER BY name"
    ).fetchall()

    if request.method == "POST":
        subject_id = request.form.get("subject_id", type=int)
        title = request.form.get("title", "").strip()
        content = request.form.get("content", "").strip()
        topic_id = request.form.get("topic_id", type=int) or None
        published = int(request.form.get("is_published") == "on")

        if not title or not content or not db.execute(
            "SELECT id FROM subjects WHERE id = ?", (subject_id,)
        ).fetchone():
            flash("Enter a title, lesson content and valid subject.", "error")
        else:
            db.execute(
                """INSERT INTO lessons
                   (subject_id, topic_id, title, content, is_published)
                   VALUES (?, ?, ?, ?, ?)""",
                (subject_id, topic_id, title, content, published)
            )
            db.commit()
            flash("Lesson saved.", "success")
            return redirect(url_for("admin_lessons"))

    lessons = db.execute(
        """SELECT l.*, s.name AS subject_name
           FROM lessons l JOIN subjects s ON s.id = l.subject_id
           ORDER BY l.created_at DESC"""
    ).fetchall()

    return render_template(
        "admin/lessons.html",
        lessons=lessons,
        subjects=subjects
    )




# -------------------------------------------------------------------
# ADMIN QUESTION EDITING AND SETTINGS
# -------------------------------------------------------------------

@app.route("/admin/questions/<int:question_id>/edit", methods=["GET", "POST"])
@admin_required
def admin_edit_question(question_id):
    db = get_db()
    question = db.execute("SELECT * FROM questions WHERE id = ?", (question_id,)).fetchone()
    if not question:
        abort(404)
    subjects = db.execute("SELECT * FROM subjects WHERE is_active = 1 ORDER BY name").fetchall()
    if request.method == "POST":
        subject_id = request.form.get("subject_id", type=int)
        topic_id = request.form.get("topic_id", type=int) or None
        question_text = request.form.get("question_text", "").strip()
        options = [request.form.get(f"option_{letter.lower()}", "").strip() for letter in "ABCD"]
        correct = request.form.get("correct_answer", "").upper()
        explanation = request.form.get("explanation", "").strip()
        year = request.form.get("exam_year", type=int)
        source = request.form.get("source", "").strip()
        published = int(request.form.get("is_published") == "on")
        valid_subject = db.execute("SELECT id FROM subjects WHERE id = ?", (subject_id,)).fetchone()
        valid_topic = not topic_id or db.execute(
            "SELECT id FROM topics WHERE id = ? AND subject_id = ?", (topic_id, subject_id)
        ).fetchone()
        if not valid_subject or not valid_topic or not question_text or any(not x for x in options) or correct not in "ABCD" or len(correct) != 1:
            flash("Check the subject, topic, question, four options and correct answer.", "error")
        else:
            db.execute("""UPDATE questions SET subject_id=?, topic_id=?, question_text=?,
                option_a=?, option_b=?, option_c=?, option_d=?, correct_answer=?,
                explanation=?, exam_year=?, source=?, is_published=? WHERE id=?""",
                (subject_id, topic_id, question_text, *options, correct, explanation, year, source, published, question_id))
            db.commit()
            flash("Question updated.", "success")
            return redirect(url_for("admin_questions"))
    return render_template("admin/question_form.html", subjects=subjects, question=question)


@app.route("/admin/settings", methods=["GET", "POST"])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == "POST":
        try:
            price = int(request.form.get("premium_price", app.config["PREMIUM_PRICE"]))
            count = int(request.form.get("practice_default_count", app.config["DEFAULT_PRACTICE_QUESTIONS"]))
            minutes = int(request.form.get("practice_default_minutes", app.config["DEFAULT_PRACTICE_MINUTES"]))
            if price < 1 or not 1 <= count <= 180 or not 1 <= minutes <= 180:
                raise ValueError
        except (TypeError, ValueError):
            flash("Enter a valid price and practice settings (1–180 for count and minutes).", "error")
        else:
            values = {"premium_price": str(price), "practice_default_count": str(count),
                      "practice_default_minutes": str(minutes)}
            for key, value in values.items():
                db.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                           (key, value))
            db.commit()
            app.config["PREMIUM_PRICE"] = price
            app.config["DEFAULT_PRACTICE_QUESTIONS"] = count
            app.config["DEFAULT_PRACTICE_MINUTES"] = minutes
            flash("Settings saved. Payment amount for new claims has been updated.", "success")
            return redirect(url_for("admin_settings"))
    rows = db.execute("SELECT key,value FROM settings").fetchall()
    settings = {row["key"]: row["value"] for row in rows}
    settings.setdefault("premium_price", str(app.config["PREMIUM_PRICE"]))
    settings.setdefault("practice_default_count", str(app.config["DEFAULT_PRACTICE_QUESTIONS"]))
    settings.setdefault("practice_default_minutes", str(app.config["DEFAULT_PRACTICE_MINUTES"]))
    return render_template("admin/settings.html", settings=settings)


# -------------------------------------------------------------------
# RULES AND ERROR PAGES
# -------------------------------------------------------------------

@app.route("/rules")
def rules():
    return render_template("rules.html")
@app.route("/arinex-promo")
def arinex_promo():
    return render_template("arinex_promo.html")



@app.errorhandler(403)
def forbidden(error):
    return render_template("error.html", code=403,
                           message="You do not have permission to access this page."), 403


@app.errorhandler(404)
def not_found(error):
    return render_template("error.html", code=404,
                           message="The requested page does not exist."), 404


@app.errorhandler(500)
def server_error(error):
    app.logger.exception("Unexpected application error")
    return (
        "<h1>Something went wrong</h1>"
        "<p>Please try again. If the problem continues, contact the administrator.</p>",
        500
    )


# -------------------------------------------------------------------
# STARTUP
# -------------------------------------------------------------------

with app.app_context():
    init_db()
    _settings = {row["key"]: row["value"] for row in get_db().execute("SELECT key, value FROM settings")}
    app.config["PREMIUM_PRICE"] = int(_settings.get("premium_price", app.config["PREMIUM_PRICE"]))
    app.config["DEFAULT_PRACTICE_QUESTIONS"] = int(_settings.get("practice_default_count", app.config["DEFAULT_PRACTICE_QUESTIONS"]))
    app.config["DEFAULT_PRACTICE_MINUTES"] = int(_settings.get("practice_default_minutes", app.config["DEFAULT_PRACTICE_MINUTES"]))


if __name__ == "__main__":
    # Local development only. Use a production WSGI server for deployment.
    app.run(debug=os.environ.get("APP_ENV") != "production")
