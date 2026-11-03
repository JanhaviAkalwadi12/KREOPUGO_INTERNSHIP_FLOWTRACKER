import os
import re
import hmac
import uuid
import sqlite3
import secrets
import smtplib
from email.message import EmailMessage
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, session, flash, send_from_directory, abort, jsonify
)
from flask.sessions import SecureCookieSessionInterface
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ==========================================================
# KREOPUGO FLOW TRACKER - app.py
# Preserves the existing kreopugo_signup.db and student rows.
# ==========================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Ensure template and static directories resolve correctly in serverless runtimes
if not os.path.isdir(os.path.join(BASE_DIR, "templates")):
    _parent_dir = os.path.abspath(os.path.join(BASE_DIR, ".."))
    if os.path.isdir(os.path.join(_parent_dir, "templates")):
        BASE_DIR = _parent_dir

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

class VercelPathFixMiddleware:
    """Ensure PATH_INFO reflects the original request path when Vercel rewrites to /api/index."""
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app

    def __call__(self, environ, start_response):
        path = environ.get("PATH_INFO", "")
        if path == "/api/index" or path.startswith("/api/index/"):
            rest = path[len("/api/index"):]
            environ["PATH_INFO"] = rest if rest.startswith("/") else ("/" + rest if rest else "/")
        return self.wsgi_app(environ, start_response)

app.wsgi_app = VercelPathFixMiddleware(app.wsgi_app)

# Vercel / serverless environment detection
IS_VERCEL = bool(
    os.environ.get("VERCEL")
    or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
    or not os.access(BASE_DIR, os.W_OK)
)

# Keep the session-signing key stable between app restarts.
# A fresh key on every restart invalidates browser sessions unexpectedly.
# You can optionally set KREOPUGO_SECRET_KEY in your environment; otherwise,
# a private key file is created once beside app.py and reused on later starts.
_SESSION_KEY_DIR = os.environ.get("TMPDIR", "/tmp") if IS_VERCEL else BASE_DIR
_SESSION_KEY_FILE = os.path.join(_SESSION_KEY_DIR, ".kreopugo_session_key")
_orig_key_file = os.path.join(BASE_DIR, ".kreopugo_session_key")
_configured_secret = os.environ.get("KREOPUGO_SECRET_KEY", "").strip()
if _configured_secret:
    app.secret_key = _configured_secret
else:
    _key_read = False
    for _kf in (_SESSION_KEY_FILE, _orig_key_file):
        try:
            if os.path.isfile(_kf):
                with open(_kf, "r", encoding="utf-8") as _key_file:
                    _val = _key_file.read().strip()
                if len(_val) >= 32:
                    app.secret_key = _val
                    _key_read = True
                    break
        except (OSError, ValueError):
            pass
    if not _key_read:
        app.secret_key = secrets.token_hex(32)
        try:
            with open(_SESSION_KEY_FILE, "w", encoding="utf-8") as _key_file:
                _key_file.write(app.secret_key)
        except OSError:
            pass

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=False,
    # No short inactivity timeout: keep a signed login cookie for 100 years.
    # Users end their login by choosing Logout or clearing their browser cookies.
    PERMANENT_SESSION_LIFETIME=timedelta(days=36500),
    SESSION_REFRESH_EACH_REQUEST=True
)


class RoleSeparatedSessionInterface(SecureCookieSessionInterface):
    """Keep each role in a different browser cookie.

    Browser cookies are shared by tabs, so a single Flask session makes an
    Admin login in one tab overwrite a Student login in another. These
    role-specific cookie names let /admin and /student use independent
    signed sessions while keeping the existing Flask session API unchanged.
    """

    def open_session(self, app, req):
        # Only the public login/landing pages use the neutral cookie. Protected
        # dashboard paths must load their own role-specific cookie; otherwise
        # every request would appear logged out after a successful login.
        path = req.path or "/"
        if path == "/login" or path == "/" or path.startswith(("/signup", "/forgot-password", "/reset-password")):
            req.environ["_kp_opening_session"] = True
            try:
                return super().open_session(app, req)
            finally:
                req.environ.pop("_kp_opening_session", None)
        return super().open_session(app, req)

    def save_session(self, app, session_obj, response):
        """Save the active role cookie and remove stale cookies for other roles.

        This prevents an old Admin/Technical/Non-Technical cookie from being
        selected after the user switches accounts in the same browser.
        """
        super().save_session(app, session_obj, response)
        role = session_obj.get("role")
        role_cookie = {
            "admin": "kp_admin_session",
            "technical": "kp_technical_session",
            "technical_head": "kp_technical_session",
            "nontechnical": "kp_nontechnical_session",
            "nontechnical_head": "kp_nontechnical_session",
            "student": "kp_student_session",
        }.get(str(role or "").strip().casefold())
        if role_cookie:
            for cookie_name in (
                "kp_login_session", "kp_admin_session", "kp_student_session",
                "kp_technical_session", "kp_nontechnical_session",
            ):
                if cookie_name != role_cookie:
                    response.delete_cookie(cookie_name, path="/")

    def get_cookie_name(self, app):
        if request.environ.get("_kp_opening_session"):
            return "kp_login_session"

        path = request.path or "/"
        if path == "/login" or path == "/" or path.startswith(("/signup", "/forgot-password", "/reset-password")):
            role = session.get("role")
            if role == "admin":
                return "kp_admin_session"
            if role == "student":
                return "kp_student_session"
            if role in ("technical", "technical_head"):
                return "kp_technical_session"
            if role in ("nontechnical", "nontechnical_head"):
                return "kp_nontechnical_session"
            return "kp_login_session"
        if path.startswith("/student/"):
            return "kp_student_session"
        if path.startswith("/assignments/") and request.args.get("role") == "student":
            return "kp_student_session"
        if path.startswith(("/admin/", "/admin", "/staff/", "/assignments/")):
            # These shared staff pages are also opened by Technical Head and
            # Non-Technical Head. Select the cookie for the staff role that is
            # currently signed in instead of always looking for the Admin cookie.
            # A successful login clears the other role cookies in save_session().
            for cookie_name in (
                "kp_admin_session",
                "kp_technical_session",
                "kp_nontechnical_session",
            ):
                if request.cookies.get(cookie_name):
                    return cookie_name
            return "kp_admin_session"
        if path.startswith("/technical/"):
            return "kp_technical_session"
        if path.startswith("/nontechnical/"):
            return "kp_nontechnical_session"
        return "kp_login_session"


app.session_interface = RoleSeparatedSessionInterface()

if IS_VERCEL:
    _TMP_DIR = os.environ.get("TMPDIR", "/tmp")
    DB_NAME = os.path.join(_TMP_DIR, "kreopugo_signup.db")
    _ORIG_DB = os.path.join(BASE_DIR, "kreopugo_signup.db")
    if not os.path.exists(DB_NAME) and os.path.exists(_ORIG_DB):
        try:
            import shutil
            shutil.copy2(_ORIG_DB, DB_NAME)
        except Exception:
            pass

    UPLOAD_FOLDER = os.path.join(_TMP_DIR, "student_uploads")
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    except Exception:
        pass

    _ORIG_UPLOADS = os.path.join(BASE_DIR, "student_uploads")
    if os.path.isdir(_ORIG_UPLOADS):
        try:
            import shutil
            for _item in os.listdir(_ORIG_UPLOADS):
                _s = os.path.join(_ORIG_UPLOADS, _item)
                _d = os.path.join(UPLOAD_FOLDER, _item)
                if not os.path.exists(_d):
                    if os.path.isdir(_s):
                        shutil.copytree(_s, _d)
                    else:
                        shutil.copy2(_s, _d)
        except Exception:
            pass
else:
    DB_NAME = os.path.join(BASE_DIR, "kreopugo_signup.db")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "student_uploads")
    try:
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    except Exception:
        pass

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
MAX_UPLOAD_SIZE = 2 * 1024 * 1024  # 2 MiB per assignment attachment or student submission
# Allow multipart/form-data overhead; each actual file is checked against MAX_UPLOAD_SIZE.
MAX_CONTENT_LENGTH = MAX_UPLOAD_SIZE + 1024 * 1024
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


# Global responsive layout: keeps existing desktop designs, while preventing
# content from overflowing on phones and tablets.
@app.after_request
def add_responsive_layout(response):
    # Dashboard HTML should be revalidated instead of restored from a stale
    # browser cache after login/role changes. Static assets remain cacheable.
    if response.mimetype == "text/html":
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    if response.mimetype == "text/html":
        html = response.get_data(as_text=True)
        if 'name="viewport"' not in html.lower():
            html = html.replace(
                "<head>",
                '<head><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">',
                1
            )
        responsive_css = r"""
<style id="kreopugo-responsive-layout">
*, *::before, *::after { box-sizing: border-box; }
html { width: 100%; max-width: 100%; overflow-x: hidden; }
body { width: 100%; max-width: 100%; margin-left: 0; margin-right: 0; overflow-x: hidden; }
img, video, canvas, iframe, svg { max-width: 100%; }
input, select, textarea, button { max-width: 100%; }
pre, code { overflow-wrap: anywhere; }
table { max-width: 100%; }
@media (max-width: 1024px) {
  .layout, .dashboard-layout, .page-layout { min-width: 0 !important; max-width: 100% !important; }
  .main, .content, .main-content, .page-content, main { min-width: 0; max-width: 100%; }
  .stats, .quick-grid, .content-grid, .grid, .cards, .card-grid, .dashboard-cards {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }
  .table-wrap, .table-responsive { max-width: 100%; overflow-x: auto; }
}
@media (max-width: 768px) {
  .layout, .dashboard-layout, .page-layout { display: block !important; width: 100% !important; }
  .sidebar { position: relative !important; top: auto !important; width: 100% !important;
    max-width: 100% !important; height: auto !important; min-height: 0 !important;
    flex: none !important; overflow: visible !important; }
  .main, .content, .main-content, .page-content, main { width: 100% !important;
    max-width: 100% !important; padding-left: 14px !important; padding-right: 14px !important; }
  .stats, .quick-grid, .content-grid, .grid, .cards, .card-grid, .dashboard-cards,
  .form-grid, .two-column, .columns { grid-template-columns: minmax(0, 1fr) !important; }
  .topbar, header, .page-header { flex-wrap: wrap; gap: 10px; }
  .nav { max-width: 100%; }
  .panel, .card, .stat-card, .content-card { min-width: 0; max-width: 100%; overflow-wrap: anywhere; }
  table { display: block; width: 100%; overflow-x: auto; white-space: nowrap; }
  input, select, textarea { min-width: 0; }
  h1 { font-size: clamp(22px, 5vw, 30px); overflow-wrap: anywhere; }
}
@media (max-width: 420px) {
  .main, .content, .main-content, .page-content, main { padding-left: 10px !important; padding-right: 10px !important; }
  .nav a { overflow-wrap: anywhere; }
  .btn, button, input[type="submit"] { max-width: 100%; white-space: normal; }
}
/* Keep dashboard sidebars fixed while the main content scrolls. */
@media (min-width: 769px) {
  body:has(.sidebar) .sidebar {
    position: fixed !important;
    top: 0 !important; left: 0 !important; bottom: 0 !important;
    height: 100vh !important; min-height: 100vh !important;
    width: 245px !important; max-width: 245px !important;
    overflow-y: auto !important; overflow-x: hidden !important;
    align-self: auto !important; z-index: 1000 !important;
  }
  body:has(.sidebar) .layout { padding-left: 245px !important; }
  body:has(.sidebar) .main { min-width: 0 !important; }
}
/* On phones, pin the navigation at the top and let the page scroll below it. */
/* Compact layout overrides for every page rendered by Flask.
   These only adjust presentation; routes, forms, links and database logic stay unchanged. */
body { font-size: 14px; line-height: 1.4; }
h1 { font-size: clamp(21px, 2.4vw, 27px) !important; margin: 0 0 6px !important; }
h2 { font-size: 18px !important; margin-top: 0; }
h3 { font-size: 15px !important; }
p { margin-top: 6px; margin-bottom: 6px; }
.panel, .card, .content-card, .stat-card, .section, .form-card {
  padding: 12px !important; border-radius: 9px !important;
}
.panel, .content-card, .section { margin-top: 12px !important; margin-bottom: 12px !important; }
label { margin: 9px 0 5px !important; font-size: 13px; }
input, select, textarea {
  padding: 9px 10px !important; font-size: 14px !important; min-height: 36px;
}
textarea { min-height: 76px; }
button, .btn, a.btn, input[type="submit"], input[type="button"] {
  padding: 8px 12px !important; font-size: 13px !important; border-radius: 6px !important;
}
table th, table td { padding: 8px 9px !important; font-size: 13px; }
.item, .list-item, .notification-item, .assignment-item {
  padding-top: 12px !important; padding-bottom: 12px !important;
}
.report-card { padding: 16px 18px !important; }
.published-announcements .item { padding: 14px 16px !important; margin: 12px 0 !important; }
.published-announcements .item p { line-height: 1.55; }
.stats, .quick-grid, .content-grid, .cards, .card-grid, .dashboard-cards, .form-grid {
  gap: 9px !important;
}
.topbar, .page-header { margin-bottom: 12px !important; gap: 10px !important; }
.nav { gap: 4px !important; }
.nav a { display: block; padding: 10px 12px !important; margin: 3px 0 !important;
  min-height: 38px; line-height: 1.35; border-radius: 8px; font-size: 13px !important; }
.nav a:hover { filter: brightness(1.08); }
.menu-badge { margin-left: 5px; }
@media (min-width: 769px) {
  body:has(.sidebar) .sidebar { width: 220px !important; max-width: 220px !important; }
  body:has(.sidebar) .layout { padding-left: 220px !important; }
  body:has(.sidebar) .main { padding: 14px 16px 20px !important; }
}
@media (max-width: 768px) {
  body:has(.sidebar) .sidebar {
    position: relative !important; top: auto !important; left: auto !important; right: auto !important;
    width: 100% !important; max-width: 100% !important; height: auto !important;
    max-height: none !important; min-height: 0 !important; overflow: visible !important;
    box-shadow: none !important;
  }
  body:has(.sidebar) .layout { display: block !important; padding-left: 0 !important; }
  body:has(.sidebar) .main { padding: 14px 12px 20px !important; }
  .sidebar .nav, nav.nav { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 3px; }
  .sidebar .brand { padding-bottom: 10px !important; font-size: 18px !important; }
  .stats, .quick-grid, .content-grid, .cards, .card-grid, .dashboard-cards, .form-grid,
  .two-column, .columns { grid-template-columns: minmax(0, 1fr) !important; }
  .topbar, .page-header { align-items: flex-start !important; flex-wrap: wrap !important; }
  .panel, .card, .content-card, .stat-card { padding: 10px !important; }
}
@media (max-width: 420px) {
  body:has(.sidebar) .main { padding: 10px !important; }
  .sidebar .nav, nav.nav { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  button, .btn, a.btn { white-space: normal !important; }
}
</style>
"""
        if 'id="kreopugo-responsive-layout"' not in html and "</head>" in html:
            html = html.replace("</head>", responsive_css + "</head>", 1)
        response.set_data(html)
    return response

COURSES = [
    "BCA", "B.Com", "BBA", "B.Sc", "B.A.", "B.Tech", "B.E.",
    "B.Pharm", "MBA", "MCA", "M.Com", "M.Sc", "M.Tech", "Other"
]
SECTIONS = ["A", "B", "C", "D", "E"]
ADMIN_ID = os.environ.get("KREOPUGO_ADMIN_ID", "admin12345")
ADMIN_PASSWORD = os.environ.get("KREOPUGO_ADMIN_PASSWORD", "admin@12345")
TECHNICAL_ID = os.environ.get("KREOPUGO_TECHNICAL_ID", "tech12345")
TECHNICAL_PASSWORD = os.environ.get("KREOPUGO_TECHNICAL_PASSWORD", "tech@12345")
NONTECHNICAL_ID = os.environ.get("KREOPUGO_NONTECHNICAL_ID", "nontech12345")
NONTECHNICAL_PASSWORD = os.environ.get("KREOPUGO_NONTECHNICAL_PASSWORD", "nontech@12345")
ALLOWED_SUBMISSION_EXTENSIONS = {
    "pdf", "doc", "docx", "txt", "zip", "jpg", "jpeg", "png"
}


def upload_exceeds_limit(file_storage):
    """Return True when an uploaded file exceeds the 2 MiB per-file limit."""
    if not file_storage or not getattr(file_storage, "stream", None):
        return False
    stream = file_storage.stream
    try:
        current = stream.tell()
        stream.seek(0, os.SEEK_END)
        size = stream.tell()
        stream.seek(current, os.SEEK_SET)
        return size > MAX_UPLOAD_SIZE
    except (OSError, AttributeError):
        # Fail closed if the stream size cannot be verified.
        return True


# -------------------- DATABASE --------------------

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def assignment_deadline_passed(value):
    """Support new date+time deadlines and older date-only assignments."""
    value = (value or "").strip()
    if not value:
        return False
    try:
        if len(value) == 10:
            # Older assignments with a date-only deadline remain open through that date.
            return datetime.now().date() > datetime.strptime(value, "%Y-%m-%d").date()
        normalized = value.replace("T", " ")
        deadline = datetime.strptime(normalized[:16], "%Y-%m-%d %H:%M")
        return datetime.now() > deadline
    except (ValueError, TypeError):
        return False


def table_columns(db, table):
    return {row["name"] for row in db.execute(
        f"PRAGMA table_info({table})"
    ).fetchall()}


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS students (
                student_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)
        # Add missing columns without deleting existing data.
        for column, definition in {
            "mobile": "TEXT", "college": "TEXT", "course": "TEXT",
            "batch": "TEXT", "address": "TEXT"
        }.items():
            if column not in table_columns(db, "students"):
                db.execute(f"ALTER TABLE students ADD COLUMN {column} {definition}")
        # New signup metadata; safe additions preserve every existing student row.
        for column, definition in {
            "year_of_passout": "TEXT NOT NULL DEFAULT ''",
            "class_type": "TEXT NOT NULL DEFAULT ''"
        }.items():
            if column not in table_columns(db, "students"):
                db.execute(f"ALTER TABLE students ADD COLUMN {column} {definition}")

        db.executescript("""
            CREATE TABLE IF NOT EXISTS batches (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_name TEXT NOT NULL UNIQUE,
                college TEXT NOT NULL,
                course TEXT NOT NULL,
                academic_year TEXT NOT NULL,
                section TEXT NOT NULL,
                capacity INTEGER NOT NULL DEFAULT 30,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assignments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                batch TEXT NOT NULL DEFAULT '',
                due_date TEXT NOT NULL DEFAULT '',
                attachment_name TEXT NOT NULL DEFAULT '',
                attachment_stored TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS announcements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS assignment_submissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assignment_id INTEGER NOT NULL,
                student_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                stored_file TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending Review',
                admin_feedback TEXT NOT NULL DEFAULT '',
                submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT,
                FOREIGN KEY (assignment_id) REFERENCES assignments(id)
            );

            CREATE TABLE IF NOT EXISTS leave_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                start_date TEXT NOT NULL,
                end_date TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_feedback TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS attendance_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                attendance_date TEXT NOT NULL,
                attendance_type TEXT NOT NULL DEFAULT 'Present',
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Pending',
                admin_feedback TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                reviewed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS student_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Keep legacy batches active by default; no existing batch is deleted.
        if "is_active" not in table_columns(db, "batches"):
            db.execute("ALTER TABLE batches ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")

        # Safe schema migration: add optional assignment-brief attachment fields
        # without deleting or changing existing assignment/student records.
        assignment_columns = table_columns(db, "assignments")
        if "attachment_name" not in assignment_columns:
            db.execute("ALTER TABLE assignments ADD COLUMN attachment_name TEXT NOT NULL DEFAULT ''")
        if "attachment_stored" not in assignment_columns:
            db.execute("ALTER TABLE assignments ADD COLUMN attachment_stored TEXT NOT NULL DEFAULT ''")

        # Safe additions for camera/location attendance; existing attendance is preserved.
        attendance_columns = table_columns(db, "attendance_requests")
        for column, definition in {
            "latitude": "TEXT NOT NULL DEFAULT ''",
            "longitude": "TEXT NOT NULL DEFAULT ''",
            "camera_photo": "TEXT NOT NULL DEFAULT ''"
        }.items():
            if column not in attendance_columns:
                db.execute(f"ALTER TABLE attendance_requests ADD COLUMN {column} {definition}")

        # Migrate existing non-empty student batch values into the new table.
        # Existing student records and batch values are not changed.
        rows = db.execute("""
            SELECT DISTINCT TRIM(batch) AS batch_name,
                   COALESCE(NULLIF(TRIM(college), ''), 'Existing student records') AS college,
                   COALESCE(NULLIF(TRIM(course), ''), 'Other') AS course
            FROM students
            WHERE batch IS NOT NULL AND TRIM(batch) != ''
        """).fetchall()
        for row in rows:
            name = row["batch_name"]
            # Only auto-import values that look like batch labels.
            db.execute("""
                INSERT OR IGNORE INTO batches
                    (batch_name, college, course, academic_year, section, capacity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (name, row["college"], row["course"], "Existing", "A", 30))


def send_student_notification(student_id, message):
    with get_db() as db:
        db.execute(
            "INSERT INTO student_notifications (student_id, message) VALUES (?, ?)",
            (student_id, message)
        )


def generate_student_id(course, year_of_passout, section, db=None):
    """Create sequential IDs such as BCA-2026-A-001 for the chosen batch."""
    course_code = re.sub(r"[^A-Za-z0-9]", "", course).upper()[:8] or "STU"
    year_code = re.sub(r"[^0-9]", "", str(year_of_passout))[-4:] or str(datetime.now().year)
    section_code = re.sub(r"[^A-Za-z0-9]", "", str(section)).upper()[:3] or "A"
    prefix = f"{course_code}-{year_code}-{section_code}-"
    owns_db = db is None
    if owns_db:
        db = get_db()
    try:
        rows = db.execute(
            "SELECT student_id FROM students WHERE student_id LIKE ?",
            (prefix + "%",)
        ).fetchall()
        used = []
        for row in rows:
            match = re.fullmatch(re.escape(prefix) + r"(\d+)", row["student_id"] or "")
            if match:
                used.append(int(match.group(1)))
        return prefix + f"{max(used, default=0) + 1:03d}"
    finally:
        if owns_db:
            db.close()


# -------------------- AUTHENTICATION --------------------


def _current_session_role():
    """Return exactly one authenticated role; never infer a role from stale flags.

    Flask's signed session cookie is shared by every tab in the same browser
    profile. An older version of the app could leave multiple role flags behind.
    An explicit role is now authoritative. Legacy sessions are accepted only
    when exactly one role's identity flags are present; ambiguous cookies fail
    closed and must sign in again.
    """
    role = session.get("role")
    if role is not None:
        aliases = {
            "admin": "admin",
            "administrator": "admin",
            "technical": "technical",
            "technical_head": "technical",
            "technical head": "technical",
            "nontechnical": "nontechnical",
            "nontechnical_head": "nontechnical",
            "non-technical head": "nontechnical",
            "student": "student",
        }
        normalized = aliases.get(str(role).strip().casefold())
        if normalized == "student" and not (session.get("student_id") or session.get("user_id")):
            return None
        return normalized

    legacy_roles = []
    if session.get("admin_logged_in") or session.get("admin"):
        legacy_roles.append("admin")
    if session.get("technical_logged_in"):
        legacy_roles.append("technical")
    if session.get("nontechnical_logged_in"):
        legacy_roles.append("nontechnical")
    if session.get("student_id") or session.get("user_id"):
        legacy_roles.append("student")
    return legacy_roles[0] if len(legacy_roles) == 1 else None


def _is_admin_session():
    return _current_session_role() == "admin"


def _is_technical_session():
    return _current_session_role() == "technical"


def _is_nontechnical_session():
    return _current_session_role() == "nontechnical"


def _is_student_session():
    return _current_session_role() == "student"


def _clear_role_session():
    """Start a clean single-role login to prevent mixed-role redirects.

    A Flask session cookie is shared across tabs. Keeping admin and student
    flags together can make generic dashboard/login redirects choose the wrong
    role. On a new successful login, remove all prior role identity keys; the
    newly authenticated role is then set by the login handler.
    """
    role_keys = (
        "admin_logged_in", "admin", "admin_id",
        "technical_logged_in", "technical_id", "technical_name",
        "nontechnical_logged_in", "nontechnical_id", "nontechnical_name",
        "student_id", "user_id", "student_name", "student_email",
        "name", "email", "role",
    )
    for key in role_keys:
        session.pop(key, None)


def admin_required(view):
    """Protect admin-only pages without bouncing an authenticated student through login.

    A student who opens an admin-only URL is kept in the student area. This
    preserves the staff-only restriction while preventing the admin warning
    from appearing on the student's dashboard after /login redirects them back.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        role = _current_session_role()
        if role == "admin":
            return view(*args, **kwargs)

        if role == "student":
            flash("That page is available only to the administrator. You are still signed in as a student.", "error")
            return redirect(url_for("student_dashboard"))
        if role == "technical":
            flash("That page is available only to the administrator.", "error")
            return redirect(url_for("technical_dashboard"))
        if role == "nontechnical":
            flash("That page is available only to the administrator.", "error")
            return redirect(url_for("nontechnical_dashboard"))

        flash("Please log in with your administrator account.", "error")
        return redirect(url_for("login"))
    return wrapped


def student_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _is_student_session():
            flash("Please log in with your student account to open this page.", "error")
            return redirect(url_for("login"))
        # Normalize compatibility session keys used by older student templates.
        if not session.get("student_id") and session.get("user_id"):
            session["student_id"] = session.get("user_id")
        return view(*args, **kwargs)
    return wrapped


def technical_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _is_technical_session():
            flash("Please log in with your Technical Head account.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_or_technical_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not (_is_admin_session() or _is_technical_session()):
            flash("Please log in with an administrator or Technical Head account.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def nontechnical_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not _is_nontechnical_session():
            flash("Please log in with your Non-Technical Head account.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_or_nontechnical_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not (_is_admin_session() or _is_nontechnical_session()):
            flash("Please log in with an administrator or Non-Technical Head account.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def admin_or_staff_required(view):
    """Allow admin/staff only; do not send a logged-in student through login."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if _is_admin_session() or _is_technical_session() or _is_nontechnical_session():
            return view(*args, **kwargs)

        # Keep student accounts out of staff-only pages. If a stale or incorrect
        # link sends a student here, return them to their own dashboard without
        # adding a staff-only warning to the dashboard itself. This does NOT
        # grant access to the protected page and does not clear their login.
        if _is_student_session():
            # Deny the staff-only route, but do not put a staff warning on the
            # student's dashboard. Any legacy warning already queued is filtered
            # by student_dashboard() above.
            return redirect(url_for("student_dashboard"))

        flash("Please log in with an authorized staff account.", "error")
        return redirect(url_for("login"))
    return wrapped


def admin_shell(title, content, **context):
    """Consistent navy header / light-grey background admin page."""
    template = """
    <!doctype html><html lang="en"><head>
    <meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{ title }} | KreoPugo</title>
    <style>
      *{box-sizing:border-box;font-family:Arial,sans-serif}
      body{margin:0;background:#F5F6F8;color:#293342}
      header{background:#173D70;color:white;padding:18px 5%;display:flex;
        align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
      header strong{font-size:16px} header a{color:white;text-decoration:none}
      main{max-width:1120px;margin:24px auto;padding:0 22px}
      .btn,button{display:inline-block;background:#781E12;color:white;border:0;
        border-radius:7px;padding:9px 13px;text-decoration:none;cursor:pointer;font-weight:bold}
      .secondary{background:#173D70}.panel{background:white;border:1px solid #E2E6EC;
        border-radius:10px;padding:20px;margin-top:16px}
      h1,h2{color:#781E12}label{display:block;font-weight:bold;margin:9px 0 5px}
      input,textarea,select{width:100%;padding:9px 10px;border:1px solid #DCE1E8;
        border-radius:7px;background:white;font-size:14px}
      .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
      .item{padding:14px 16px;margin:12px 0;background:#F7F9FC;border:1px solid #E2E6EC;
        border-radius:9px;overflow-wrap:anywhere}
      .item:last-child{border-bottom:0}.muted{color:#6B7280;font-size:13px}
      .flash{padding:12px;border-radius:7px;background:#EAF1FA;color:#173D70}
      .flash.error{background:#FBEAE6;color:#781E12}.flash.success{background:#E7F5EA;color:#216536}
      table{width:100%;border-collapse:collapse;min-width:700px}
      th,td{text-align:left;padding:12px;border-bottom:1px solid #E2E6EC}
      th{background:#EAF1FA;color:#173D70}.table-wrap{overflow-x:auto}
      @media(max-width:650px){.grid{grid-template-columns:1fr}.panel{padding:17px}}
    </style></head><body>
    <header><strong>KreoPugo | {{ title }}</strong>
      <a href="{{ url_for('logout') }}" onclick="return confirm('Log out?')">Logout</a>
    </header><main>
      <a class="btn secondary" href="{{ dashboard_url }}">{{ dashboard_label }}</a>
      {% with messages=get_flashed_messages(with_categories=true) %}
        {% for category,message in messages %}<p class="flash {{ category }}">{{ message }}</p>{% endfor %}
      {% endwith %}
      <section class="panel">{{ content|safe }}</section>
    </main></body></html>
    """
    # Choose the dashboard from the single canonical role, never from stale
    # compatibility flags that could point to a different role's dashboard.
    current_role = _current_session_role()
    if current_role == "admin":
        dashboard_label, dashboard_url = "← Admin Dashboard", url_for("admin_dashboard")
    elif current_role == "technical":
        dashboard_label, dashboard_url = "← Technical Dashboard", url_for("technical_dashboard")
    elif current_role == "nontechnical":
        dashboard_label, dashboard_url = "← Non-Technical Dashboard", url_for("nontechnical_dashboard")
    elif current_role == "student":
        dashboard_label, dashboard_url = "← Student Dashboard", url_for("student_dashboard")
    else:
        dashboard_label, dashboard_url = "← Login", url_for("login")
    return render_template_string(
        template,
        title=title,
        content=content,
        dashboard_label=dashboard_label,
        dashboard_url=dashboard_url,
        **context
    )


def student_shell(title, content):
    template = """
    <!doctype html><html lang="en"><head><meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>{{ title }} | KreoPugo</title><style>
    *{box-sizing:border-box;font-family:Arial,sans-serif}body{margin:0;background:#F5F6F8;color:#293342}
    header{background:#173D70;color:white;padding:18px 5%;display:flex;justify-content:space-between;gap:12px}
    header a{color:white;text-decoration:none}main{max-width:1000px;margin:28px auto;padding:0 18px}
    .panel{background:white;border:1px solid #E2E6EC;border-radius:12px;padding:22px;margin:18px 0}
    h2{color:#781E12}a.btn,button{display:inline-block;background:#781E12;color:white;border:0;border-radius:7px;
    padding:10px 15px;text-decoration:none;cursor:pointer}label{display:block;font-weight:bold;margin:12px 0 7px}
    input,textarea,select{width:100%;padding:11px;border:1px solid #DCE1E8;border-radius:7px}
    .item{padding:14px 0;border-bottom:1px solid #E2E6EC}.muted{color:#6B7280;font-size:13px}
    .flash{padding:12px;background:#EAF1FA;border-radius:7px}
    </style></head><body><header><strong>KreoPugo | {{ title }}</strong>
    <a href="{{ url_for('logout') }}">Logout</a></header><main>
    <a class="btn" style="background:#173D70" href="{{ url_for('student_dashboard') }}">← Student Dashboard</a>
    {% with messages=get_flashed_messages(with_categories=true) %}
    {% for category,message in messages %}<p class="flash">{{ message }}</p>{% endfor %}{% endwith %}
    <section class="panel">{{ content|safe }}</section></main></body></html>
    """
    return render_template_string(template, title=title, content=content)


# -------------------- HOME / SIGNUP / LOGIN --------------------

@app.route("/")
@app.route("/index")
@app.route("/index.html")
def landing_page():
    # Route to the one explicitly authenticated role only.
    if _is_admin_session():
        return redirect(url_for("admin_dashboard"))
    if _is_technical_session():
        return redirect(url_for("technical_dashboard"))
    if _is_nontechnical_session():
        return redirect(url_for("nontechnical_dashboard"))
    if _is_student_session():
        return redirect(url_for("student_dashboard"))
    # Render the project's original landing page from templates/landing_page.html.
    return render_template("landing_page.html")


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "GET":
        current_year = datetime.now().year
        return render_template(
            "signup.html",
            courses=COURSES,
            passout_years=list(range(current_year, current_year + 8))
        )

    # Read the field names used by the existing signup.html form.
    # The fallbacks keep compatibility with older copies of the form.
    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()
    mobile = request.form.get("phone", request.form.get("mobile", "")).strip()
    college = request.form.get("college", "").strip()
    course_input = request.form.get("course", "").strip()
    course = {"BA": "B.A."}.get(course_input, course_input)
    batch = request.form.get("batch_id", request.form.get("batch", "")).strip()
    year_of_passout = request.form.get("year_of_passout", "").strip()
    class_type = request.form.get("class_type", "").strip()
    address = request.form.get("address", "").strip()
    password = request.form.get("password", "")
    confirm = request.form.get("confirm_password", "")

    if not all([name, email, mobile, college, course, batch,
                year_of_passout, class_type, password, confirm]):
        flash("Please complete all required fields.", "error")
        return redirect(url_for("signup"))

    if course not in COURSES:
        flash("Please select a valid course.", "error")
        return redirect(url_for("signup"))

    if class_type not in ("Internship", "Project", "Both"):
        flash("Please select a valid class type.", "error")
        return redirect(url_for("signup"))

    if not year_of_passout.isdigit() or len(year_of_passout) != 4:
        flash("Select a valid year of passout.", "error")
        return redirect(url_for("signup"))

    # The supplied form has no terms checkbox, so do not reject its submission
    # for a field that the user cannot see or complete.
    if len(password) < 6:
        flash("Password must contain at least 6 characters.", "error")
        return redirect(url_for("signup"))

    if password != confirm:
        flash("Passwords do not match.", "error")
        return redirect(url_for("signup"))

    if not re.fullmatch(r"[6-9]\d{9}", mobile):
        flash("Enter a valid 10-digit Indian mobile number.", "error")
        return redirect(url_for("signup"))

    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        flash("Enter a valid email address.", "error")
        return redirect(url_for("signup"))

    try:
        with get_db() as db:
            # Server-side validation is authoritative: the selected batch must
            # belong to the exact college and course entered in this signup.
            batch_row = db.execute("""
                SELECT id, batch_name, college, course, academic_year,
                       section, capacity, is_active
                FROM batches
                WHERE LOWER(TRIM(batch_name)) = LOWER(TRIM(?))
                  AND LOWER(TRIM(college)) = LOWER(TRIM(?))
                  AND LOWER(TRIM(course)) = LOWER(TRIM(?))
                  AND COALESCE(is_active, 1) = 1
                LIMIT 1
            """, (batch, college, course)).fetchone()

            if not batch_row:
                flash(
                    "No active batch matches the selected college and course. "
                    "Please choose a matching batch.",
                    "error"
                )
                return redirect(url_for("signup"))

            count = db.execute("""
                SELECT COUNT(*)
                FROM students
                WHERE LOWER(TRIM(COALESCE(batch, ''))) = LOWER(TRIM(?))
            """, (batch_row["batch_name"],)).fetchone()[0]

            if count >= int(batch_row["capacity"] or 0):
                flash("This batch is full. Please select another available batch.", "error")
                return redirect(url_for("signup"))

            student_id = generate_student_id(
                course, year_of_passout, batch_row["section"], db=db
            )

            db.execute("""
                INSERT INTO students
                    (student_id, name, email, password_hash, created_at, mobile,
                     college, course, batch, address, year_of_passout, class_type)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                student_id, name, email, generate_password_hash(password),
                now_text(), mobile, college, course, batch_row["batch_name"],
                address, year_of_passout, class_type
            ))

    except sqlite3.IntegrityError:
        flash("This email is already registered. Please log in.", "error")
        return redirect(url_for("signup"))

    email_sent = send_account_created_email(student_id, name, email, password)
    if email_sent:
        flash(
            f"Signup successful. Your student ID is {student_id}. "
            f"Welcome email sent to {email}.",
            "success"
        )
    else:
        flash(
            f"Signup successful. Your student ID is {student_id}. Keep it safe for login.",
            "success"
        )
    return redirect(url_for("login"))


@app.route("/signup/batches", methods=["GET"])
def signup_batches():
    """Return active batches for the exact college/course, excluding full batches."""
    college = request.args.get("college", "").strip()
    course_input = request.args.get("course", "").strip()
    course = {"BA": "B.A."}.get(course_input, course_input)

    if not college or course not in COURSES:
        return jsonify([])

    with get_db() as db:
        rows = db.execute("""
            SELECT b.id, b.batch_name, b.academic_year, b.section, b.capacity,
                   (
                       SELECT COUNT(*)
                       FROM students s
                       WHERE LOWER(TRIM(COALESCE(s.batch, ''))) =
                             LOWER(TRIM(b.batch_name))
                   ) AS enrolled
            FROM batches b
            WHERE LOWER(TRIM(b.college)) = LOWER(TRIM(?))
              AND LOWER(TRIM(b.course)) = LOWER(TRIM(?))
              AND COALESCE(b.is_active, 1) = 1
            ORDER BY b.academic_year DESC, b.section, b.batch_name
        """, (college, course)).fetchall()

    result = []
    for row in rows:
        capacity = int(row["capacity"] or 0)
        available = max(0, capacity - int(row["enrolled"] or 0))
        if available > 0:
            result.append({
                "id": row["id"],
                "batch_name": row["batch_name"],
                "academic_year": row["academic_year"],
                "section": row["section"],
                "available": available
            })

    return jsonify(result)


# Backward-compatible endpoint alias for signup templates using either name.
app.add_url_rule(
    "/signup/batches",
    endpoint="get_signup_batches",
    view_func=signup_batches,
    methods=["GET"]
)


LOGIN_PAGE_HTML = r"""
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>KREOPUGO | Login</title>
  <style>
    *{box-sizing:border-box} body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(135deg,#fff4f1,#f7e8e5);font-family:Arial,sans-serif;color:#342321}
    .login-card{width:min(100%,430px);background:#fff;border-radius:20px;padding:34px;box-shadow:0 18px 55px rgba(91,45,38,.14)}
    .brand{font-size:13px;font-weight:800;letter-spacing:3px;color:#9a5148;text-align:center;margin-bottom:8px}
    h1{text-align:center;font-size:27px;margin:0 0 8px} .sub{text-align:center;color:#786966;margin:0 0 26px;font-size:14px}
    label{display:block;font-size:13px;font-weight:700;margin:15px 0 7px}
    input{width:100%;padding:13px 14px;border:1px solid #dfcfcb;border-radius:10px;font-size:15px;outline:none}
    input:focus{border-color:#a85e53;box-shadow:0 0 0 3px rgba(168,94,83,.12)}
    button{width:100%;border:0;border-radius:10px;padding:14px;margin-top:22px;background:#8e4038;color:#fff;font-size:15px;font-weight:700;cursor:pointer}
    button:hover{background:#71312b}.links{text-align:center;margin-top:18px;font-size:13px}.links a{color:#8e4038;text-decoration:none;font-weight:700}
    .message{padding:11px 13px;border-radius:9px;margin:8px 0;font-size:13px;background:#fff0ed;color:#8a3028}
    .message.success{background:#edf8ef;color:#276238}.message.warning{background:#fff7e5;color:#805b13}
  </style>
</head>
<body><main class="login-card">
  <div class="brand">KREOPUGO</div><h1>Welcome Back</h1><p class="sub">Sign in to continue to your dashboard</p>
  {% with messages = get_flashed_messages(with_categories=true) %}
    {% for category, message in messages %}<div class="message {{ category }}">{{ message }}</div>{% endfor %}
  {% endwith %}
  <form method="post" action="{{ url_for('login') }}" autocomplete="on">
    <label for="name">Name</label><input id="name" name="name" type="text" placeholder="Enter your name" autocomplete="name" required>
    <label for="user_id">ID</label><input id="user_id" name="user_id" type="text" placeholder="Enter your ID" autocomplete="username" required>
    <label for="password">Password</label><input id="password" name="password" type="password" placeholder="Enter your password" autocomplete="current-password" required>
    <button type="submit">Login</button>
  </form>
  <div class="links"><a href="{{ url_for('forgot_password') }}">Forgot password?</a> &nbsp;|&nbsp; <a href="{{ url_for('signup') }}">Student sign up</a></div>
</main></body></html>
"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # If already logged in, do not show the login page when the browser Back
        # button returns to /login. Send the user to their own dashboard instead.
        # Check the explicit role first so old mixed-role cookies are handled
        # predictably. New logins clear old role keys in _clear_role_session().
        # A logged-in user returns to their own dashboard. Ambiguous old
        # cookies deliberately show the login page instead of guessing a role.
        if _is_admin_session():
            return redirect(url_for("admin_dashboard"))
        if _is_technical_session():
            return redirect(url_for("technical_dashboard"))
        if _is_nontechnical_session():
            return redirect(url_for("nontechnical_dashboard"))
        if _is_student_session():
            return redirect(url_for("student_dashboard"))
        return render_template_string(LOGIN_PAGE_HTML)

    name = request.form.get("name", "").strip()
    user_id = request.form.get("user_id", "").strip()
    password = request.form.get("password", "")
    if not name or not user_id or not password:
        flash("Enter your name, ID and password.", "error")
        return redirect(url_for("login"))

    if (user_id.casefold() == ADMIN_ID.casefold()
            and ADMIN_PASSWORD
            and hmac.compare_digest(password, ADMIN_PASSWORD)
            and name.casefold() in ("administrator", "admin")):
        _clear_role_session()
        session.permanent = True
        session["admin_logged_in"] = True
        session["admin"] = True
        session["admin_id"] = ADMIN_ID
        session["role"] = "admin"
        return redirect(url_for("admin_dashboard"))

    # Technical Head login uses the shared login form.
    if (user_id.casefold() == TECHNICAL_ID.casefold()
            and TECHNICAL_PASSWORD
            and hmac.compare_digest(password, TECHNICAL_PASSWORD)
            and name.casefold() in ("technical head", "technical_head", "technical")):
        _clear_role_session()
        session.permanent = True
        session["technical_logged_in"] = True
        session["technical_id"] = TECHNICAL_ID
        session["technical_name"] = "Janhavi Akalwadi"
        session["role"] = "technical_head"
        return redirect(url_for("technical_dashboard"))

    # Non-Technical Head login uses the same login page.
    if (user_id.casefold() == NONTECHNICAL_ID.casefold()
            and NONTECHNICAL_PASSWORD
            and hmac.compare_digest(password, NONTECHNICAL_PASSWORD)
            and name.casefold() in ("non-technical head", "non technical head", "nontechnical head", "nontechnical", "non-technical", "non technical")):
        _clear_role_session()
        session.permanent = True
        session["nontechnical_logged_in"] = True
        session["nontechnical_id"] = NONTECHNICAL_ID
        session["nontechnical_name"] = "Praveen Deshpande"
        session["role"] = "nontechnical_head"
        return redirect(url_for("nontechnical_dashboard"))

    with get_db() as db:
        student = db.execute("""
            SELECT student_id,name,email,password_hash FROM students WHERE student_id=?
        """, (user_id,)).fetchone()

    if (student and student["name"].strip().casefold() == name.casefold()
            and check_password_hash(student["password_hash"], password)):
        _clear_role_session()
        session.permanent = True
        session["student_id"] = student["student_id"]
        session["user_id"] = student["student_id"]
        session["role"] = "student"
        session["student_name"] = student["name"]
        session["student_email"] = student["email"]
        # Compatibility keys used by the student dashboard template.
        session["name"] = student["name"]
        session["email"] = student["email"]
        return redirect(url_for("student_dashboard"))

    flash("Invalid name, ID or password.", "error")
    return redirect(url_for("login"))


# -------------------- FORGOT / RESET STUDENT PASSWORD --------------------

def password_reset_serializer():
    # Uses the same secret key as Flask sessions; configure KREOPUGO_SECRET_KEY
    # to a long random value before deployment.
    return URLSafeTimedSerializer(app.secret_key, salt="kreopugo-password-reset")


def send_account_created_email(student_id, student_name, recipient, password):
    """Email a new student their KreoPugo account details using configured SMTP."""
    smtp_host = os.environ.get("KREOPUGO_SMTP_HOST", "").strip()
    try:
        smtp_port = int(os.environ.get("KREOPUGO_SMTP_PORT", "587"))
    except ValueError:
        return False
    smtp_user = os.environ.get("KREOPUGO_SMTP_USER", "").strip()
    smtp_password = os.environ.get("KREOPUGO_SMTP_PASSWORD", "")
    sender = os.environ.get("KREOPUGO_RESET_SENDER", smtp_user).strip()

    if not all([smtp_host, smtp_user, smtp_password, sender]):
        return False

    message = EmailMessage()
    message["Subject"] = "Welcome to Kreo & Pugo - Your Student Account"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        f"Dear {student_name},\n\n"
        "Welcome to Kreo & Pugo! Your student account has been created successfully.\n\n"
        f"Student ID: {student_id}\n"
        f"Registered email: {recipient}\n"
        f"Temporary / account password: {password}\n\n"
        "Please keep these details private and change your password after signing in.\n"
        "You can sign in through the Kreo & Pugo Flow Pilot login page.\n\n"
        "Welcome aboard,\nKreo & Pugo Team"
    )
    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.send_message(message)
        return True
    except (OSError, smtplib.SMTPException, ValueError):
        return False


def send_password_reset_email(recipient, reset_url):
    """Send a time-limited reset link using SMTP environment settings."""
    smtp_host = os.environ.get("KREOPUGO_SMTP_HOST", "").strip()
    smtp_port = int(os.environ.get("KREOPUGO_SMTP_PORT", "587"))
    smtp_user = os.environ.get("KREOPUGO_SMTP_USER", "").strip()
    smtp_password = os.environ.get("KREOPUGO_SMTP_PASSWORD", "")
    sender = os.environ.get("KREOPUGO_RESET_SENDER", smtp_user).strip()

    if not all([smtp_host, smtp_user, smtp_password, sender]):
        return False

    message = EmailMessage()
    message["Subject"] = "Reset your KreoPugo password"
    message["From"] = sender
    message["To"] = recipient
    message.set_content(
        "We received a request to reset your KreoPugo Flow Tracker password.\\n\\n"
        f"Open this link within 30 minutes to choose a new password:\\n{reset_url}\\n\\n"
        "If you did not request this, you can ignore this email."
    )
    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(message)
    return True


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        student_id = request.form.get("student_id", "").strip()
        email = request.form.get("email", "").strip().lower()

        if not student_id or not email:
            flash("Enter your student ID and registered email address.", "error")
            return redirect(url_for("forgot_password"))

        with get_db() as db:
            student = db.execute(
                "SELECT student_id,email FROM students "
                "WHERE student_id=? AND lower(email)=lower(?)",
                (student_id, email)
            ).fetchone()

        # Do not reveal whether an ID/email pair belongs to an account.
        if student:
            token = password_reset_serializer().dumps({
                "student_id": student["student_id"],
                "email": student["email"].lower()
            })
            reset_url = url_for("reset_password", token=token, _external=True)
            try:
                sent = send_password_reset_email(student["email"], reset_url)
            except (OSError, smtplib.SMTPException, ValueError) as exc:
                app.logger.error("Password reset email failed: %s", exc)
                sent = False

            if not sent:
                flash(
                    "Email delivery is not configured or failed. Set the KREOPUGO_SMTP_* "
                    "environment variables in your development environment, then try again.",
                    "error"
                )
                return redirect(url_for("forgot_password"))

        flash(
            "If the student ID and registered email match, a password-reset link "
            "will be sent to that email address.",
            "success"
        )
        return redirect(url_for("login"))

    page = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Forgot Password | KreoPugo</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#F5F6F8;color:#293342;padding:20px}
.card{width:100%;max-width:440px;background:#fff;border:1px solid #DCE3ED;border-radius:14px;padding:28px;box-shadow:0 12px 35px #173D7012}
h1{color:#173D70;font-size:25px;margin:0 0 8px}p{line-height:1.5;color:#64748b}
label{display:block;margin:16px 0 7px;font-weight:bold;color:#293342}
input{width:100%;padding:12px;border:1px solid #DCE1E8;border-radius:7px;font-size:15px}
button{width:100%;margin-top:20px;background:#781E12;color:#fff;border:0;border-radius:7px;padding:12px;font-weight:bold;cursor:pointer}
a{color:#173D70;text-decoration:none}.flash{padding:11px;border-radius:7px;background:#EAF1FA;color:#173D70}.flash.error{background:#FBEAE6;color:#781E12}
</style></head><body><main class="card">
<h1>Forgot Password?</h1><p>Enter your student ID and the email address registered with your KreoPugo account. We will email you a secure reset link.</p>
{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<p class="flash {{ category }}">{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
<label for="student_id">Student ID</label><input id="student_id" name="student_id" required autocomplete="username">
<label for="email">Registered email</label><input id="email" type="email" name="email" required autocomplete="email">
<button type="submit">Send Reset Link</button>
</form><p><a href="{{ url_for('login') }}">← Back to Login</a></p>
</main></body></html>"""
    return render_template_string(page)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    try:
        payload = password_reset_serializer().loads(token, max_age=1800)
        student_id = payload.get("student_id")
        email = payload.get("email", "").lower()
    except SignatureExpired:
        flash("This password-reset link has expired. Request a new one.", "error")
        return redirect(url_for("forgot_password"))
    except (BadSignature, AttributeError, TypeError):
        flash("This password-reset link is invalid. Request a new one.", "error")
        return redirect(url_for("forgot_password"))

    with get_db() as db:
        student = db.execute(
            "SELECT student_id,email FROM students WHERE student_id=? AND lower(email)=?",
            (student_id, email)
        ).fetchone()

    if not student:
        flash("This password-reset link is invalid. Request a new one.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            with get_db() as db:
                db.execute(
                    "UPDATE students SET password_hash=? WHERE student_id=? AND lower(email)=?",
                    (generate_password_hash(password), student_id, email)
                )
            flash("Your password has been reset. Please log in with your new password.", "success")
            return redirect(url_for("login"))

    page = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Reset Password | KreoPugo</title>
<style>
*{box-sizing:border-box;font-family:Arial,sans-serif}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#F5F6F8;color:#293342;padding:20px}
.card{width:100%;max-width:440px;background:#fff;border:1px solid #DCE3ED;border-radius:14px;padding:28px}
h1{color:#173D70;font-size:25px}label{display:block;margin:16px 0 7px;font-weight:bold}
input{width:100%;padding:12px;border:1px solid #DCE1E8;border-radius:7px;font-size:15px}
button{width:100%;margin-top:20px;background:#781E12;color:#fff;border:0;border-radius:7px;padding:12px;font-weight:bold;cursor:pointer}
.flash{padding:11px;border-radius:7px;background:#FBEAE6;color:#781E12}
</style></head><body><main class="card"><h1>Set a New Password</h1>
<p>Choose a password with at least 8 characters.</p>
{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<p class="flash">{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
<label for="password">New password</label><input id="password" type="password" name="password" minlength="8" required autocomplete="new-password">
<label for="confirm_password">Confirm new password</label><input id="confirm_password" type="password" name="confirm_password" minlength="8" required autocomplete="new-password">
<button type="submit">Reset Password</button>
</form></main></body></html>"""
    return render_template_string(page)


@app.route("/dashboard")
def dashboard_home():
    """Return to the dashboard for the one explicitly authenticated role."""
    role = session.get("role")

    # Use the explicit role first so a stale compatibility flag cannot send
    # someone to a different dashboard.
    if role in ("admin",) and _is_admin_session():
        return redirect(url_for("admin_dashboard"))
    if role in ("technical", "technical_head", "technical head") and _is_technical_session():
        return redirect(url_for("technical_dashboard"))
    if role in ("nontechnical", "nontechnical_head", "non-technical head") and _is_nontechnical_session():
        return redirect(url_for("nontechnical_dashboard"))
    if role == "student" and _is_student_session():
        return redirect(url_for("student_dashboard"))

    # Ambiguous or invalid sessions are never redirected to another role.
    # Ask the user to sign in again rather than guessing a dashboard.
    flash("Please log in again to continue to your correct dashboard.", "error")
    return redirect(url_for("login"))


# -------------------- ADMIN DASHBOARD --------------------


@app.route("/admin")
@admin_required
def admin_dashboard():
    """Admin dashboard."""

    with get_db() as db:

        # DASHBOARD COUNTS
        total_students = db.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        total_batches = db.execute(
            "SELECT COUNT(*) FROM batches"
        ).fetchone()[0]

        total_assignments = db.execute(
            "SELECT COUNT(*) FROM assignments"
        ).fetchone()[0]

        total_submissions = db.execute(
            "SELECT COUNT(*) FROM assignment_submissions"
        ).fetchone()[0]

        pending_submissions = db.execute(
            """SELECT COUNT(*) FROM assignment_submissions
               WHERE status='Pending Review'"""
        ).fetchone()[0]

        total_attendance = db.execute(
            "SELECT COUNT(*) FROM attendance_requests"
        ).fetchone()[0]

        pending_leaves = db.execute(
            """SELECT COUNT(*) FROM leave_requests
               WHERE status='Pending'"""
        ).fetchone()[0]

        pending_attendance = db.execute(
            """SELECT COUNT(*) FROM attendance_requests
               WHERE status='Pending'"""
        ).fetchone()[0]

        admin_notification_count = (
            pending_submissions +
            pending_leaves +
            pending_attendance
        )

        # RECENT SUBMISSIONS
        recent_submissions = db.execute("""
            SELECT
                s.id,
                s.student_id,
                s.file_name,
                s.status,
                s.submitted_at,
                a.title,
                st.name AS student_name

            FROM assignment_submissions s

            LEFT JOIN assignments a
                ON a.id = s.assignment_id

            LEFT JOIN students st
                ON st.student_id = s.student_id

            ORDER BY s.id DESC
            LIMIT 6
        """).fetchall()

        # RECENT ATTENDANCE
        recent_attendance = db.execute("""
            SELECT
                a.id,
                a.student_id,
                a.attendance_date,
                a.attendance_type,
                a.status,
                a.created_at,
                st.name AS student_name

            FROM attendance_requests a

            LEFT JOIN students st
                ON st.student_id = a.student_id

            ORDER BY a.id DESC
            LIMIT 5
        """).fetchall()

        # STUDENT PROGRESS
        student_progress = db.execute("""

            SELECT
                st.student_id,
                st.name,
                st.batch,
                st.course,

                (
                    SELECT COUNT(*)
                    FROM assignments a
                    WHERE LOWER(TRIM(COALESCE(a.batch,'')))
                    IN (
                        LOWER(TRIM(COALESCE(st.batch,''))),
                        'all'
                    )
                ) AS assigned_count,

                (
                    SELECT COUNT(DISTINCT sub.assignment_id)
                    FROM assignment_submissions sub

                    JOIN assignments a
                    ON a.id = sub.assignment_id

                    WHERE sub.student_id = st.student_id

                    AND LOWER(TRIM(COALESCE(a.batch,'')))
                    IN (
                        LOWER(TRIM(COALESCE(st.batch,''))),
                        'all'
                    )
                ) AS submitted_count,

                (
                    SELECT COUNT(*)
                    FROM assignment_submissions sub

                    JOIN assignments a
                    ON a.id = sub.assignment_id

                    WHERE sub.student_id = st.student_id

                    AND LOWER(TRIM(COALESCE(a.batch,'')))
                    IN (
                        LOWER(TRIM(COALESCE(st.batch,''))),
                        'all'
                    )

                    AND LOWER(TRIM(COALESCE(sub.status,'')))
                    = 'approved'
                ) AS approved_count,

                (
                    SELECT COUNT(*)
                    FROM attendance_requests ar

                    WHERE ar.student_id = st.student_id

                    AND LOWER(TRIM(COALESCE(ar.status,'')))
                    IN ('approved','present','accepted')
                ) AS attendance_record_count,

                (
                    SELECT COUNT(*)
                    FROM attendance_requests ar

                    WHERE ar.student_id = st.student_id

                    AND LOWER(TRIM(COALESCE(ar.attendance_type,'')))
                    = 'present'

                    AND LOWER(TRIM(COALESCE(ar.status,'')))
                    IN ('approved','present','accepted')
                ) AS present_count

            FROM students st

            ORDER BY st.name COLLATE NOCASE

        """).fetchall()

    # SEND DATA TO HTML
    return render_template(

        "admin_dashboard.html",

        total_students=total_students,
        total_batches=total_batches,
        total_assignments=total_assignments,
        total_submissions=total_submissions,

        pending_submissions=pending_submissions,
        total_attendance=total_attendance,

        pending_leaves=pending_leaves,
        pending_attendance=pending_attendance,

        admin_notification_count=admin_notification_count,

        recent_submissions=recent_submissions,
        recent_attendance=recent_attendance,

        student_progress=student_progress

    )

# -------------------- ADMIN NOTIFICATIONS --------------------
@app.route("/admin/notifications")
@admin_required
def admin_notifications():
    """Show outstanding student activity that needs admin attention."""

    with get_db() as db:

        pending_submissions = db.execute("""
            SELECT s.id, s.student_id, s.file_name, s.submitted_at,
                   a.title,
                   st.name AS student_name
            FROM assignment_submissions s
            LEFT JOIN assignments a
                ON a.id = s.assignment_id
            LEFT JOIN students st
                ON st.student_id = s.student_id
            WHERE COALESCE(s.status, 'Pending Review') = 'Pending Review'
            ORDER BY s.id DESC
        """).fetchall()

        pending_leaves = db.execute("""
            SELECT l.id, l.student_id, l.start_date, l.end_date,
                   l.reason, l.created_at,
                   st.name AS student_name
            FROM leave_requests l
            LEFT JOIN students st
                ON st.student_id = l.student_id
            WHERE COALESCE(l.status, 'Pending') = 'Pending'
            ORDER BY l.id DESC
        """).fetchall()

        pending_attendance = db.execute("""
            SELECT a.id, a.student_id, a.attendance_date,
                   a.attendance_type, a.reason, a.created_at,
                   st.name AS student_name
            FROM attendance_requests a
            LEFT JOIN students st
                ON st.student_id = a.student_id
            WHERE COALESCE(a.status, 'Pending') = 'Pending'
            ORDER BY a.id DESC
        """).fetchall()

    return admin_shell(
        "Notifications",
        render_template(
            "admin_notifications.html",
            pending_submissions=pending_submissions,
            pending_leaves=pending_leaves,
            pending_attendance=pending_attendance
        )
    )
# -------------------- BATCH MANAGEMENT --------------------

@app.route("/admin/batches", methods=["GET", "POST"])
@admin_or_staff_required
def admin_batches():
    """Create batches and display registered students."""

    if request.method == "POST":

        action = request.form.get("action", "create_batch")

        if action == "add_student":
            flash(
                "Students must create their own accounts using Student Signup. "
                "Admins can manage batches and view registered students here.",
                "error"
            )
            return redirect(url_for("admin_batches"))

        college = request.form.get("college", "").strip()
        course = request.form.get("course", "").strip()
        academic_year = request.form.get("academic_year", "").strip()
        section = request.form.get("section", "").strip().upper()
        batch_name = request.form.get("batch_name", "").strip()
        capacity = request.form.get("capacity", type=int)

        expected_name = (
            f"{course}-{academic_year.split('-')[0]}-{section}"
            if academic_year and "-" in academic_year
            else ""
        )

        if (
            not college
            or course not in COURSES
            or not academic_year
            or section not in SECTIONS
        ):
            flash("Complete all batch fields with valid values.", "error")

        elif not re.fullmatch(r"\d{4}-\d{4}", academic_year):
            flash("Select a valid academic year.", "error")

        elif batch_name != expected_name:
            flash(
                "Generated batch name is invalid. "
                "Please reselect course, year and section.",
                "error"
            )

        elif capacity is None or capacity < 30:
            flash("Student capacity must be at least 30.", "error")

        else:
            try:
                with get_db() as db:
                    db.execute("""
                        INSERT INTO batches (
                            batch_name,
                            college,
                            course,
                            academic_year,
                            section,
                            capacity
                        )
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (
                        batch_name,
                        college,
                        course,
                        academic_year,
                        section,
                        capacity
                    ))

                flash("Batch created successfully.", "success")

            except sqlite3.IntegrityError:
                flash(
                    "This batch name already exists. "
                    "Choose another academic year or section.",
                    "error"
                )

        return redirect(url_for("admin_batches"))

    # Fetch existing batches and student records.
    with get_db() as db:

        batches = db.execute("""
            SELECT
                b.id,
                b.batch_name,
                b.college,
                b.course,
                b.academic_year,
                b.section,
                b.capacity,

                (
                    SELECT COUNT(*)
                    FROM students s
                    WHERE TRIM(COALESCE(s.batch, '')) = b.batch_name
                ) AS student_count

            FROM batches b
            ORDER BY
                b.academic_year DESC,
                b.course,
                b.section
        """).fetchall()

        recent_students = db.execute("""
            SELECT
                student_id,
                name,
                email,
                college,
                course,
                batch,
                created_at
            FROM students
            ORDER BY created_at DESC
            LIMIT 30
        """).fetchall()

    years = [
        f"{y}-{y + 1}"
        for y in range(
            datetime.now().year - 2,
            datetime.now().year + 3
        )
    ]

    return admin_shell(
        "Batch Management",
        render_template(
            "batch_management.html",
            batches=batches,
            recent_students=recent_students,
            courses=COURSES,
            years=years,
            sections=SECTIONS
        )
    )


# Alias for templates using the batch_management endpoint.
app.add_url_rule(
    "/admin/batches",
    endpoint="batch_management",
    view_func=admin_batches,
    methods=["GET", "POST"]
)
# -------------------- STAFF STUDENT DETAILS / PROGRESS --------------------

@app.route("/staff/students/<student_id>", methods=["GET", "POST"])
@admin_or_staff_required
def staff_student_detail(student_id):
    """Staff-only student record editor and progress overview."""

    with get_db() as db:

        student = db.execute(
            """
            SELECT student_id, name, email, mobile, college,
                   course, batch, address, created_at
            FROM students
            WHERE student_id=?
            """,
            (student_id,)
        ).fetchone()

        if not student:
            flash("Student not found.", "error")
            return redirect(url_for("admin_batches"))

        # Update student details
        if request.method == "POST":

            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            mobile = request.form.get("mobile", "").strip()
            college = request.form.get("college", "").strip()
            course = request.form.get("course", "").strip()
            batch = request.form.get("batch", "").strip()
            address = request.form.get("address", "").strip()

            if not name or not email:
                flash("Student name and email are required.", "error")

            elif not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+", email
            ):
                flash("Enter a valid email address.", "error")

            elif mobile and not re.fullmatch(r"[6-9]\d{9}", mobile):
                flash(
                    "Mobile must be a valid 10-digit Indian number or left blank.",
                    "error"
                )

            else:
                valid_batch = True

                if batch:
                    valid_batch = db.execute(
                        "SELECT 1 FROM batches WHERE batch_name=?",
                        (batch,)
                    ).fetchone() is not None

                if not valid_batch:
                    flash(
                        "Choose an existing batch or leave Batch unassigned.",
                        "error"
                    )

                else:
                    try:
                        db.execute("""
                            UPDATE students
                            SET name=?,
                                email=?,
                                mobile=?,
                                college=?,
                                course=?,
                                batch=?,
                                address=?
                            WHERE student_id=?
                        """, (
                            name,
                            email,
                            mobile or None,
                            college,
                            course,
                            batch or None,
                            address,
                            student_id
                        ))

                        db.execute("""
                            INSERT INTO student_notifications
                                (student_id, message)
                            VALUES (?, ?)
                        """, (
                            student_id,
                            "Your student profile details were updated by the institute."
                        ))

                        flash(
                            "Student details updated successfully.",
                            "success"
                        )

                    except sqlite3.IntegrityError:
                        flash(
                            "That email address is already used by another student.",
                            "error"
                        )

                    return redirect(
                        url_for(
                            "staff_student_detail",
                            student_id=student_id
                        )
                    )

        # Refresh student details
        student = db.execute(
            """
            SELECT student_id, name, email, mobile, college,
                   course, batch, address, created_at
            FROM students
            WHERE student_id=?
            """,
            (student_id,)
        ).fetchone()

        batch_name = (student["batch"] or "").strip()

        # Assignment statistics
        assigned_count = db.execute(
            """
            SELECT COUNT(*)
            FROM assignments
            WHERE batch='All' OR TRIM(batch)=?
            """,
            (batch_name,)
        ).fetchone()[0]

        submission_count = db.execute(
            """
            SELECT COUNT(*)
            FROM assignment_submissions
            WHERE student_id=?
            """,
            (student_id,)
        ).fetchone()[0]

        pending_submissions = db.execute(
            """
            SELECT COUNT(*)
            FROM assignment_submissions
            WHERE student_id=? AND status='Pending Review'
            """,
            (student_id,)
        ).fetchone()[0]

        approved_submissions = db.execute(
            """
            SELECT COUNT(*)
            FROM assignment_submissions
            WHERE student_id=? AND status='Approved'
            """,
            (student_id,)
        ).fetchone()[0]

        # Attendance statistics
        attendance_count = db.execute(
            """
            SELECT COUNT(*)
            FROM attendance_requests
            WHERE student_id=?
            """,
            (student_id,)
        ).fetchone()[0]

        pending_attendance = 0

        # Leave statistics
        leave_count = db.execute(
            """
            SELECT COUNT(*)
            FROM leave_requests
            WHERE student_id=?
            """,
            (student_id,)
        ).fetchone()[0]

        pending_leaves = db.execute(
            """
            SELECT COUNT(*)
            FROM leave_requests
            WHERE student_id=? AND status='Pending'
            """,
            (student_id,)
        ).fetchone()[0]

        # Assignment progress
        assignments = db.execute("""
            SELECT
                a.id,
                a.title,
                a.due_date,

                (
                    SELECT s.status
                    FROM assignment_submissions s
                    WHERE s.assignment_id=a.id
                      AND s.student_id=?
                    ORDER BY s.id DESC
                    LIMIT 1
                ) AS submission_status,

                (
                    SELECT s.submitted_at
                    FROM assignment_submissions s
                    WHERE s.assignment_id=a.id
                      AND s.student_id=?
                    ORDER BY s.id DESC
                    LIMIT 1
                ) AS submitted_at

            FROM assignments a

            WHERE a.batch='All' OR TRIM(a.batch)=?

            ORDER BY a.due_date ASC, a.id DESC
        """, (
            student_id,
            student_id,
            batch_name
        )).fetchall()

        # Submitted files
        submissions = db.execute("""
            SELECT
                s.id,
                s.file_name,
                s.status,
                s.admin_feedback,
                s.submitted_at,
                a.title

            FROM assignment_submissions s

            LEFT JOIN assignments a
                ON a.id=s.assignment_id

            WHERE s.student_id=?

            ORDER BY s.id DESC
            LIMIT 30
        """, (student_id,)).fetchall()

        # Attendance history
        attendance_rows = db.execute(
            """
            SELECT attendance_date,
                   attendance_type,
                   status,
                   created_at
            FROM attendance_requests
            WHERE student_id=?
            ORDER BY attendance_date DESC, id DESC
            LIMIT 30
            """,
            (student_id,)
        ).fetchall()

        # Leave history
        leave_rows = db.execute(
            """
            SELECT start_date,
                   end_date,
                   reason,
                   status,
                   admin_feedback,
                   created_at
            FROM leave_requests
            WHERE student_id=?
            ORDER BY id DESC
            LIMIT 20
            """,
            (student_id,)
        ).fetchall()

        # Available batches
        batches = db.execute(
            """
            SELECT batch_name
            FROM batches
            ORDER BY batch_name
            """
        ).fetchall()

    return render_template(
        "staff_student_detail.html",
        student=student,
        batches=batches,
        assigned_count=assigned_count,
        submission_count=submission_count,
        pending_submissions=pending_submissions,
        approved_submissions=approved_submissions,
        attendance_count=attendance_count,
        pending_attendance=pending_attendance,
        leave_count=leave_count,
        pending_leaves=pending_leaves,
        assignments=assignments,
        submissions=submissions,
        attendance_rows=attendance_rows,
        leave_rows=leave_rows
    )

# -------------------- STUDENT ADMISSION --------------------

@app.route("/admin/student-admission", methods=["GET", "POST"])
@admin_or_staff_required
def student_admission():
    if request.method == "POST":
        flash("Student admission records are currently created through the signup workflow.", "info")
        return redirect(url_for("student_admission"))
    with get_db() as db:
        students = db.execute("""
            SELECT student_id,name,email,mobile,college,course,batch,created_at
            FROM students ORDER BY created_at DESC
        """).fetchall()
        batches = db.execute("SELECT batch_name FROM batches ORDER BY batch_name").fetchall()
    content = """
    <h2>Student Admission</h2>
    <p>Students create their own accounts through Student Signup. This page is read-only and lists registered students.</p>
    <p><a class="btn" href="{{ url_for('admin_batches') }}">Open Batch Management</a></p>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Email</th>
    <th>College</th><th>Course</th><th>Batch</th></tr></thead><tbody>
    {% for s in students %}<tr><td>{{ s['student_id'] }}</td><td><a href="{{ url_for('staff_student_detail', student_id=s['student_id']) }}">{{ s['name'] }}</a></td>
    <td>{{ s['email'] }}</td><td>{{ s['college'] or '-' }}</td><td>{{ s['course'] or '-' }}</td>
    <td>{{ s['batch'] or '-' }}</td></tr>{% else %}<tr><td colspan="6">No students found.</td></tr>
    {% endfor %}</tbody></table></div>
    """
    return render_template_string("""
    <!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Student Admission</title><style>body{margin:0;background:#F5F6F8;font-family:Arial;color:#293342}
    header{background:#173D70;color:white;padding:18px 5%;display:flex;justify-content:space-between}
    header a{color:white}main{max-width:1100px;margin:30px auto;padding:0 18px}.panel{background:white;padding:24px;border-radius:12px}
    h2{color:#781E12}table{width:100%;border-collapse:collapse;min-width:700px}th,td{text-align:left;padding:12px;border-bottom:1px solid #ddd}
    th{background:#EAF1FA;color:#173D70}.wrap{overflow:auto}.btn{display:inline-block;background:#173D70;color:white;padding:10px 14px;border-radius:7px;text-decoration:none;margin:20px 0}</style>
    </head><body><header><strong>KreoPugo | Student Admission</strong><a href="{{ url_for('logout') }}">Logout</a></header>
    <main><a class="btn" href="{{ url_for('admin_dashboard') }}">Back to Dashboard</a><section class="panel">
    {{ content|safe }}</section></main></body></html>
    """, content=render_template_string(content, students=students, batches=batches),
       )


# -------------------- MENTOR ASSIGNMENT MANAGEMENT --------------------

@app.route("/admin/assignments", methods=["GET", "POST"])
@admin_or_staff_required
def admin_assignments():
    """Compact assignment list with inline student approval actions."""

    if request.method == "POST":

        action = request.form.get("action", "").strip()

        # Approve or reject a student submission
        if action == "review_submission":

            submission_id = request.form.get("submission_id", type=int)
            decision = request.form.get("decision", "").strip()

            if not submission_id or decision not in {"Approved", "Rejected"}:
                flash("Invalid submission action. Please try again.", "error")
                return redirect(url_for("admin_assignments"))

            with get_db() as db:

                record = db.execute("""
                    SELECT id, student_id, assignment_id
                    FROM assignment_submissions
                    WHERE id=?
                """, (submission_id,)).fetchone()

                if not record:
                    flash("Student submission was not found.", "error")
                    return redirect(url_for("admin_assignments"))

                db.execute("""
                    UPDATE assignment_submissions
                    SET status=?,
                        reviewed_at=CURRENT_TIMESTAMP
                    WHERE id=?
                """, (decision, submission_id))

                db.execute("""
                    INSERT INTO student_notifications(student_id, message)
                    VALUES(?, ?)
                """, (
                    record["student_id"],
                    f"Your assignment submission has been {decision.lower()}."
                ))

            flash(
                f"Submission {decision.lower()} successfully.",
                "success"
            )

            return redirect(
                url_for("admin_assignments") + f"#submission-{submission_id}"
            )

        # Create a new assignment
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        batch = request.form.get("batch", "").strip()
        due_date = request.form.get("due_date", "").strip()
        attachment = request.files.get("assignment_file")

        if not all([title, description, batch, due_date]):
            flash("Complete every required assignment field.", "error")
            return redirect(url_for("admin_assignments"))

        with get_db() as db:

            if batch != "All":

                existing_batch = db.execute(
                    "SELECT 1 FROM batches WHERE batch_name=?",
                    (batch,)
                ).fetchone()

                if not existing_batch:
                    flash("Select a valid batch.", "error")
                    return redirect(url_for("admin_assignments"))

            attachment_name = ""
            attachment_stored = ""

            if attachment and attachment.filename:

                safe_name = secure_filename(attachment.filename)

                ext = (
                    safe_name.rsplit(".", 1)[-1].lower()
                    if "." in safe_name
                    else ""
                )

                if upload_exceeds_limit(attachment):
                    flash(
                        "Assignment attachment must be 2 MB or smaller.",
                        "error"
                    )
                    return redirect(url_for("admin_assignments"))

                if not safe_name or ext not in ALLOWED_SUBMISSION_EXTENSIONS:
                    flash(
                        "Instruction attachment must be PDF, DOC, DOCX, TXT, ZIP, JPG or PNG.",
                        "error"
                    )
                    return redirect(url_for("admin_assignments"))

                attachment_name = safe_name
                attachment_stored = uuid.uuid4().hex + "_" + safe_name

                attachment.save(
                    os.path.join(UPLOAD_FOLDER, attachment_stored)
                )

            db.execute("""
                INSERT INTO assignments (
                    title,
                    description,
                    batch,
                    due_date,
                    attachment_name,
                    attachment_stored,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                title,
                description,
                batch,
                due_date,
                attachment_name,
                attachment_stored,
                now_text()
            ))

        flash(
            "Assignment published. Students in the selected batch can now submit their work.",
            "success"
        )

        return redirect(url_for("admin_assignments"))

    # Load assignments, batches and student submissions
    with get_db() as db:

        assignments = db.execute("""
            SELECT *
            FROM assignments
            ORDER BY id DESC
        """).fetchall()

        batches = db.execute("""
            SELECT batch_name
            FROM batches
            ORDER BY batch_name
        """).fetchall()

        all_submissions = db.execute("""
            SELECT
                s.id,
                s.assignment_id,
                s.student_id,
                s.file_name,
                s.stored_file,
                s.status,
                s.submitted_at,
                s.admin_feedback,
                st.name AS student_name

            FROM assignment_submissions s

            LEFT JOIN students st
                ON st.student_id = s.student_id

            ORDER BY s.id DESC
        """).fetchall()

    # Group submissions under their assignments
    submissions_by_assignment = {}

    for submission in all_submissions:

        submissions_by_assignment.setdefault(
            submission["assignment_id"], []
        ).append(submission)

    assignment_groups = [
        {
            "assignment": assignment,
            "submissions": submissions_by_assignment.get(
                assignment["id"], []
            )
        }
        for assignment in assignments
    ]

    # Count submissions that still need review
    pending_submissions = sum(
        1
        for sub in all_submissions
        if (sub["status"] or "Pending Review").lower()
        not in {"approved", "rejected"}
    )

    return admin_shell(
        "Assignments",
        render_template(
            "admin_assignments.html",
            assignment_groups=assignment_groups,
            batches=batches,
            pending_submissions=pending_submissions
        )
    )

@app.route("/admin/assignments/<int:assignment_id>/edit", methods=["GET", "POST"])
@admin_or_staff_required
def edit_assignment(assignment_id):
    """Mentor-only edit page for the assignment brief; not for student submissions."""
    with get_db() as db:
        assignment = db.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()
        batches = db.execute("SELECT batch_name FROM batches ORDER BY batch_name").fetchall()

    if not assignment:
        flash("Assignment not found.", "error")
        return redirect(url_for("admin_assignments"))

    if request.method == "POST":
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        batch = request.form.get("batch", "").strip()
        due_date = request.form.get("due_date", "").strip()
        attachment = request.files.get("assignment_file")
        if not all([title, description, batch, due_date]):
            flash("Complete every assignment field.", "error")
        elif batch != "All" and not any(b["batch_name"] == batch for b in batches):
            flash("Select a valid batch.", "error")
        else:
            replacement_name = ""
            replacement_stored = ""
            if attachment and attachment.filename:
                safe_name = secure_filename(attachment.filename)
                ext = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
                if upload_exceeds_limit(attachment):
                    flash("Assignment attachment must be 2 MB or smaller.", "error")
                    return redirect(url_for("edit_assignment", assignment_id=assignment_id))
                if not safe_name or ext not in ALLOWED_SUBMISSION_EXTENSIONS:
                    flash("Attachment must be PDF, DOC, DOCX, TXT, ZIP, JPG or PNG.", "error")
                    return redirect(url_for("edit_assignment", assignment_id=assignment_id))
                replacement_name = safe_name
                replacement_stored = uuid.uuid4().hex + "_" + safe_name
                attachment.save(os.path.join(UPLOAD_FOLDER, replacement_stored))
            with get_db() as db:
                if replacement_stored:
                    db.execute(
                        """UPDATE assignments SET title=?,description=?,batch=?,due_date=?,
                           attachment_name=?,attachment_stored=? WHERE id=?""",
                        (title, description, batch, due_date, replacement_name, replacement_stored, assignment_id)
                    )
                else:
                    db.execute(
                        "UPDATE assignments SET title=?, description=?, batch=?, due_date=? WHERE id=?",
                        (title, description, batch, due_date, assignment_id)
                    )
            flash("Assignment updated successfully.", "success")
            return redirect(url_for("admin_assignments"))
        with get_db() as db:
            assignment = db.execute("SELECT * FROM assignments WHERE id = ?", (assignment_id,)).fetchone()

    content = """
    <h2>Edit Assignment</h2>
    <p>Only authorized staff can edit the assignment brief. Student work remains submitted by the student.</p>
    <form method="post" enctype="multipart/form-data">
      <label>Assignment Title</label><input name="title" maxlength="200" value="{{ a['title'] }}" required>
      <label>Instructions</label><textarea name="description" rows="4" required>{{ a['description'] }}</textarea>
      <label>Batch</label><select name="batch" required>
        <option value="All" {% if a['batch'] == 'All' %}selected{% endif %}>All batches</option>
        {% for b in batches %}<option value="{{ b['batch_name'] }}" {% if a['batch'] == b['batch_name'] %}selected{% endif %}>{{ b['batch_name'] }}</option>{% endfor %}
      </select>
      <label>Assignment Deadline (date and time)</label><input type="datetime-local" name="due_date" value="{{ a['due_date'][:16]|replace(' ', 'T') if a['due_date'] else '' }}" required>
      <p class="muted">Students can submit until this exact time. After the deadline, the assignment stays visible but uploading is closed.</p>
      {% if a['attachment_name'] %}<p>Current attachment: {{ a['attachment_name'] }}</p>{% endif %}
      <label>Replace / Add Instruction Attachment (optional)</label><input type="file" name="assignment_file" accept=".pdf,.doc,.docx,.txt,.zip,.jpg,.jpeg,.png">
      <p class="muted">Leave this blank to keep the current attachment.</p>
      <p style="margin-top:16px"><button type="submit">Save Assignment Changes</button> <a class="btn secondary" href="{{ url_for('admin_assignments') }}">Cancel</a></p>
    </form>
    """
    return admin_shell("Edit Assignment", render_template_string(content, a=assignment, batches=batches))


@app.route("/assignments/<int:assignment_id>/attachment")
def download_assignment_attachment(assignment_id):
    """Serve assignment instructions only to logged-in students assigned to it or staff."""
    is_staff = (
        session.get("admin_logged_in") is True or session.get("admin") is True
        or session.get("technical_logged_in") is True
        or session.get("nontechnical_logged_in") is True
    )
    student_id = session.get("student_id")
    if not is_staff and not student_id:
        return redirect(url_for("login"))

    with get_db() as db:
        assignment = db.execute(
            "SELECT id,batch,attachment_name,attachment_stored FROM assignments WHERE id=?",
            (assignment_id,)
        ).fetchone()
        if not assignment:
            abort(404)
        if not is_staff:
            student = db.execute(
                "SELECT batch FROM students WHERE student_id=?", (student_id,)
            ).fetchone()
            student_batch = (student["batch"] or "").strip() if student else ""
            if not student or (assignment["batch"] or "").strip() not in ("All", student_batch):
                abort(403)

    stored = os.path.basename(assignment["attachment_stored"] or "")
    if not stored or not os.path.isfile(os.path.join(UPLOAD_FOLDER, stored)):
        abort(404)
    return send_from_directory(
        UPLOAD_FOLDER, stored, as_attachment=True,
        download_name=os.path.basename(assignment["attachment_name"] or stored)
    )


@app.route("/staff/submissions/<int:submission_id>/download")
@admin_or_staff_required
def download_submission(submission_id):
    """Only authorized staff can download a student's submitted file for review."""
    with get_db() as db:
        submission = db.execute(
            "SELECT stored_file, file_name FROM assignment_submissions WHERE id = ?",
            (submission_id,)
        ).fetchone()
    if not submission:
        abort(404)
    stored_file = os.path.basename(submission["stored_file"] or "")
    full_path = os.path.join(UPLOAD_FOLDER, stored_file)
    if not stored_file or not os.path.isfile(full_path):
        abort(404)
    return send_from_directory(
        UPLOAD_FOLDER, stored_file, as_attachment=True,
        download_name=os.path.basename(submission["file_name"] or stored_file)
    )


@app.route("/admin/submissions/<int:submission_id>/review", methods=["GET", "POST"])
@admin_or_staff_required
def review_assignment_submission(submission_id):
    """Show one student's submission details and let authorized staff approve/reject it."""
    if request.method == "POST":
        decision = request.form.get("decision", "").strip()
        feedback = request.form.get("feedback", "").strip()
        if decision not in {"Approved", "Rejected"}:
            flash("Choose Approve or Reject to continue.", "error")
            return redirect(url_for("review_assignment_submission", submission_id=submission_id))
        with get_db() as db:
            record = db.execute("""
                SELECT s.id, s.student_id, s.assignment_id
                FROM assignment_submissions s WHERE s.id=?
            """, (submission_id,)).fetchone()
            if not record:
                flash("Student submission was not found.", "error")
                return redirect(url_for("admin_assignments"))
            db.execute("""
                UPDATE assignment_submissions
                SET status=?, admin_feedback=?, reviewed_at=CURRENT_TIMESTAMP
                WHERE id=?
            """, (decision, feedback, submission_id))
            message = f"Your assignment submission has been {decision.lower()}."
            if feedback:
                message += f" Mentor feedback: {feedback}"
            db.execute("INSERT INTO student_notifications(student_id,message) VALUES(?,?)",
                       (record["student_id"], message))
        flash(f"Submission {decision.lower()} and student notified.", "success")
        return redirect(url_for("admin_assignments"))

    with get_db() as db:
        submission = db.execute("""
            SELECT s.*, a.title AS assignment_title, a.description AS assignment_description,
                   st.name AS student_name
            FROM assignment_submissions s
            LEFT JOIN assignments a ON a.id=s.assignment_id
            LEFT JOIN students st ON st.student_id=s.student_id
            WHERE s.id=?
        """, (submission_id,)).fetchone()
    if not submission:
        flash("Student submission was not found.", "error")
        return redirect(url_for("admin_assignments"))

    content = """
    <style>
      .review-head{display:flex;justify-content:space-between;align-items:center;gap:12px}
      .close-x{display:inline-flex;align-items:center;justify-content:center;width:38px;height:38px;border-radius:50%;background:#fbe8e7;color:#781e12;text-decoration:none;font-size:23px;font-weight:bold}
      .detail-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px;margin:20px 0}
      .detail-field{background:#f5f7fb;border:1px solid #e2e6ec;border-radius:8px;padding:13px;min-width:0}
      .detail-field label{margin:0 0 7px;color:#64748b;font-size:12px}
      .detail-field input{background:#fff}
      .decision-row{display:flex;gap:10px;flex-wrap:wrap;margin-top:18px}
      .approve{background:#237443}.reject{background:#a51d1d}
      @media(max-width:600px){.detail-grid{grid-template-columns:1fr}}
    </style>
    <div class="review-head"><div><h2>Review Student Submission</h2><p>Check the student and assignment details, then approve or reject the work.</p></div>
      <a class="close-x" title="Close and go back" aria-label="Close" href="{{ url_for('admin_assignments') }}">×</a>
    </div>
    <form method="post">
      <div class="detail-grid">
        <div class="detail-field"><label>Student Name</label><input value="{{ submission['student_name'] or submission['student_id'] }}" readonly></div>
        <div class="detail-field"><label>Student ID</label><input value="{{ submission['student_id'] }}" readonly></div>
        <div class="detail-field"><label>Assignment</label><input value="{{ submission['assignment_title'] or 'Assignment' }}" readonly></div>
        <div class="detail-field"><label>Submission Date</label><input value="{{ (submission['submitted_at'] or '').split(' ')[0] }}" readonly></div>
        <div class="detail-field"><label>Submission Time</label><input value="{{ (submission['submitted_at'] or '').split(' ')[1] if ' ' in (submission['submitted_at'] or '') else 'Not available' }}" readonly></div>
        <div class="detail-field"><label>Current Status</label><input value="{{ submission['status'] }}" readonly></div>
      </div>
      <p><strong>Submitted file:</strong> {{ submission['file_name'] or 'No filename recorded' }}</p>
      <p><a class="btn secondary" href="{{ url_for('download_submission', submission_id=submission['id']) }}">Download Student File</a></p>
      <label for="feedback">Mentor Feedback (optional)</label>
      <textarea id="feedback" name="feedback" rows="4" maxlength="2000" placeholder="Write feedback for the student...">{{ submission['admin_feedback'] or '' }}</textarea>
      <div class="decision-row">
        <button class="approve" type="submit" name="decision" value="Approved" onclick="return confirm('Approve this assignment submission?')">✓ Approve</button>
        <button class="reject" type="submit" name="decision" value="Rejected" onclick="return confirm('Reject this assignment submission?')">✕ Reject</button>
        <a class="btn secondary" href="{{ url_for('admin_assignments') }}">← Back</a>
      </div>
    </form>
    """
    return admin_shell("Review Student Submission", render_template_string(content, submission=submission))


# -------------------- ADMIN ANNOUNCEMENTS --------------------

@app.route("/admin/announcements", methods=["GET", "POST"])
@admin_or_staff_required
def admin_announcements():
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        message = request.form.get("message", "").strip()
        if not title or not message:
            flash("Enter an announcement title and message.", "error")
        else:
            with get_db() as db:
                db.execute(
                    "INSERT INTO announcements(title,message,created_at) VALUES(?,?,?)",
                    (title, message, now_text())
                )
            flash("Announcement published to student dashboards.", "success")
        return redirect(url_for("admin_announcements"))
    with get_db() as db:
        announcements = db.execute("SELECT * FROM announcements ORDER BY id DESC").fetchall()
    content = """
    <h2>Publish an Announcement</h2>
    <form class="announcement-form" method="post"><label>Announcement Title</label><input name="title" required maxlength="200">
    <label>Message</label><textarea name="message" rows="5" required></textarea>
    <button type="submit">Publish Announcement</button></form>
    <style>.announcement-form{display:grid;gap:8px}.announcement-form input,.announcement-form textarea{margin-bottom:8px}.published-announcements{margin-top:24px;padding-top:8px;border-top:1px solid #E2E6EC}.published-announcements h2{margin-bottom:14px}.published-announcements .item{padding:15px 17px;margin:12px 0}.published-announcements .item h3{margin:0 0 8px;color:#173D70}.published-announcements .item p{line-height:1.55;margin:6px 0}@media(min-width:700px){.announcement-form textarea{min-height:120px}}</style>
    <div class="published-announcements"><h2>Published Announcements</h2>
    {% for a in announcements %}<article class="item"><h3>{{ a['title'] }}</h3><p>{{ a['message'] }}</p>
    <p class="muted">{{ a['created_at'] }}</p></article>{% else %}<p>No announcements published yet.</p>{% endfor %}</div>
    """
    return admin_shell("Announcement Management", render_template_string(content, announcements=announcements))




# -------------------- TECHNICAL HEAD DASHBOARD --------------------

@app.route("/technical/dashboard")
@technical_required
def technical_dashboard():
    """Technical Head dashboard: live assignment, submission and attendance overview."""

    with get_db() as db:

        total_students = db.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        total_batches = db.execute(
            "SELECT COUNT(*) FROM batches"
        ).fetchone()[0]

        total_assignments = db.execute(
            "SELECT COUNT(*) FROM assignments"
        ).fetchone()[0]

        total_submissions = db.execute(
            "SELECT COUNT(*) FROM assignment_submissions"
        ).fetchone()[0]

        pending_submissions = db.execute(
            "SELECT COUNT(*) FROM assignment_submissions WHERE status='Pending Review'"
        ).fetchone()[0]

        total_attendance = db.execute(
            "SELECT COUNT(*) FROM attendance_requests"
        ).fetchone()[0]

        submissions = db.execute("""
            SELECT
                s.id,
                s.student_id,
                s.file_name,
                s.status,
                s.submitted_at,
                a.title,
                st.name AS student_name
            FROM assignment_submissions s
            LEFT JOIN assignments a ON a.id = s.assignment_id
            LEFT JOIN students st ON st.student_id = s.student_id
            ORDER BY s.id DESC
            LIMIT 10
        """).fetchall()

        attendance = db.execute("""
            SELECT
                r.id,
                r.student_id,
                r.attendance_date,
                r.attendance_type,
                r.status,
                st.name AS student_name
            FROM attendance_requests r
            LEFT JOIN students st ON st.student_id = r.student_id
            ORDER BY r.id DESC
            LIMIT 10
        """).fetchall()

    return render_template(
        "technical_dashboard.html",
        total_students=total_students,
        total_batches=total_batches,
        total_assignments=total_assignments,
        total_submissions=total_submissions,
        pending_submissions=pending_submissions,
        total_attendance=total_attendance,
        submissions=submissions,
        attendance=attendance
    )

# -------------------- NON-TECHNICAL HEAD DASHBOARD --------------------

@app.route("/nontechnical/dashboard")
@nontechnical_required
def nontechnical_dashboard():
    """Overview for student records, batches, announcements, leave and attendance."""

    with get_db() as db:

        total_students = db.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        total_batches = db.execute(
            "SELECT COUNT(*) FROM batches"
        ).fetchone()[0]

        total_announcements = db.execute(
            "SELECT COUNT(*) FROM announcements"
        ).fetchone()[0]

        pending_leaves = db.execute(
            "SELECT COUNT(*) FROM leave_requests WHERE status='Pending'"
        ).fetchone()[0]

        total_attendance = db.execute(
            "SELECT COUNT(*) FROM attendance_requests"
        ).fetchone()[0]

        recent_students = db.execute("""
            SELECT student_id, name, email, college, course, batch, created_at
            FROM students
            ORDER BY created_at DESC
            LIMIT 8
        """).fetchall()

        recent_leaves = db.execute("""
            SELECT
                l.student_id,
                l.start_date,
                l.end_date,
                l.status,
                l.created_at,
                COALESCE(s.name, l.student_id) AS student_name
            FROM leave_requests l
            LEFT JOIN students s ON s.student_id = l.student_id
            ORDER BY l.id DESC
            LIMIT 8
        """).fetchall()

        recent_attendance = db.execute("""
            SELECT
                a.student_id,
                a.attendance_date,
                a.attendance_type,
                a.status,
                a.created_at,
                COALESCE(s.name, a.student_id) AS student_name
            FROM attendance_requests a
            LEFT JOIN students s ON s.student_id = a.student_id
            ORDER BY a.id DESC
            LIMIT 8
        """).fetchall()

    return render_template(
        "non-technical.html",
        total_students=total_students,
        total_batches=total_batches,
        total_announcements=total_announcements,
        pending_leaves=pending_leaves,
        total_attendance=total_attendance,
        recent_students=recent_students,
        recent_leaves=recent_leaves,
        recent_attendance=recent_attendance
    )


#----------------STUDENT DASHBOARD---------------------------------------------

@app.route("/student/dashboard")
@student_required
def student_dashboard():
    """Student home page with working links to assignments, attendance and leave.

    Remove only stale staff-only warning messages left by an older version.
    """
    stale_staff_warnings = (
        "this page is available only to authorized staff accounts",
        "please log in with an authorized staff account",
        "this page is available only to authorized staff",
    )

    queued_flashes = session.get("_flashes", [])

    if queued_flashes:
        session["_flashes"] = [
            item for item in queued_flashes
            if not any(
                phrase in str(item[1]).casefold()
                for phrase in stale_staff_warnings
            )
        ]

        if not session["_flashes"]:
            session.pop("_flashes", None)

    student_id = session.get("student_id")

    with get_db() as db:

        student_row = db.execute(
            "SELECT * FROM students WHERE student_id = ?",
            (student_id,)
        ).fetchone()

        if not student_row:
            session.clear()
            flash("Student record not found. Please log in again.", "error")
            return redirect(url_for("login"))

        student = dict(student_row)
        batch = (student.get("batch") or "").strip()

        assignments = db.execute("""
            SELECT a.*,
                   (
                       SELECT s.status
                       FROM assignment_submissions s
                       WHERE s.assignment_id = a.id
                         AND s.student_id = ?
                       ORDER BY s.id DESC
                       LIMIT 1
                   ) AS submission_status
            FROM assignments a
            WHERE TRIM(a.batch) = ?
               OR TRIM(a.batch) = 'All'
            ORDER BY a.due_date ASC, a.id DESC
            LIMIT 5
        """, (student_id, batch)).fetchall()

        total_assignments = db.execute(
            """
            SELECT COUNT(*)
            FROM assignments
            WHERE TRIM(batch) = ?
               OR TRIM(batch) = 'All'
            """,
            (batch,)
        ).fetchone()[0]

        submitted_count = db.execute(
            """
            SELECT COUNT(DISTINCT assignment_id)
            FROM assignment_submissions
            WHERE student_id = ?
            """,
            (student_id,)
        ).fetchone()[0]

        announcements = db.execute(
            """
            SELECT *
            FROM announcements
            ORDER BY id DESC
            LIMIT 5
            """
        ).fetchall()

        notifications = db.execute(
            """
            SELECT *
            FROM student_notifications
            WHERE student_id = ?
            ORDER BY id DESC
            LIMIT 5
            """,
            (student_id,)
        ).fetchall()

        unread_notifications = db.execute(
            """
            SELECT COUNT(*)
            FROM student_notifications
            WHERE student_id = ?
              AND COALESCE(is_read, 0) = 0
            """,
            (student_id,)
        ).fetchone()[0]

    return render_template(
        "student_dashboard.html",
        student=student,
        assignments=assignments,
        total_assignments=total_assignments,
        submitted_count=submitted_count,
        announcements=announcements,
        notifications=notifications,
        unread_notifications=unread_notifications
    )

# -------------------- STUDENT ASSIGNMENTS / SUBMISSIONS --------------------

@app.route("/student/assignments", methods=["GET", "POST"])
@student_required
def student_assignments():
    """Students can upload only their own work for assignments assigned to their batch."""
    student_id = session["student_id"]

    if request.method == "POST":
        assignment_id = request.form.get("assignment_id", type=int)
        uploaded = request.files.get("submission_file")
        with get_db() as db:
            student = db.execute(
                "SELECT batch FROM students WHERE student_id = ?", (student_id,)
            ).fetchone()
            assignment = db.execute(
                "SELECT * FROM assignments WHERE id = ?", (assignment_id,)
            ).fetchone()
            student_batch = (student["batch"] or "").strip() if student else ""

            if not student:
                session.clear()
                flash("Your student record could not be found. Please log in again.", "error")
                return redirect(url_for("login"))
            if not assignment:
                flash("Assignment not found.", "error")
            elif (assignment["batch"] or "").strip() not in ("All", student_batch):
                flash("This assignment is not assigned to your batch.", "error")
            elif assignment_deadline_passed(assignment["due_date"]):
                flash("The submission deadline has passed. You can still view the assignment, but uploads are closed.", "error")
            elif not uploaded or not uploaded.filename:
                flash("Choose a file to submit.", "error")
            else:
                previous = db.execute("""
                    SELECT status FROM assignment_submissions
                    WHERE assignment_id = ? AND student_id = ?
                    ORDER BY id DESC LIMIT 1
                """, (assignment_id, student_id)).fetchone()
                previous_status = previous["status"] if previous else None
                if previous_status in ("Pending Review", "Approved"):
                    flash("Your work has already been submitted. Wait for mentor review before submitting again.", "error")
                else:
                    filename = secure_filename(uploaded.filename)
                    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
                    if not filename or ext not in ALLOWED_SUBMISSION_EXTENSIONS:
                        flash("File type not allowed. Upload PDF, DOC, DOCX, TXT, ZIP, JPG or PNG.", "error")
                    elif upload_exceeds_limit(uploaded):
                        flash("Your assignment submission must be 2 MB or smaller.", "error")
                    else:
                        stored = uuid.uuid4().hex + "_" + filename
                        uploaded.save(os.path.join(UPLOAD_FOLDER, stored))
                        db.execute("""
                            INSERT INTO assignment_submissions(assignment_id,student_id,file_name,stored_file,status,admin_feedback,submitted_at)
                            VALUES(?,?,?,?,?,?,?)
                        """, (assignment_id, student_id, filename, stored, "Pending Review", "", now_text()))
                        db.execute(
                            "INSERT INTO student_notifications(student_id,message) VALUES(?,?)",
                            (student_id, "Your assignment submission was received and is awaiting mentor review.")
                        )
                        flash("Assignment submitted successfully. Your mentor can now review it.", "success")
        return redirect(url_for("student_assignments"))

    with get_db() as db:
        student = db.execute(
            "SELECT batch FROM students WHERE student_id = ?", (student_id,)
        ).fetchone()
        batch = (student["batch"] or "").strip() if student else ""
        assignments = db.execute("""
            SELECT a.*,
                (SELECT s.status FROM assignment_submissions s
                 WHERE s.assignment_id = a.id AND s.student_id = ?
                 ORDER BY s.id DESC LIMIT 1) AS submission_status,
                (SELECT s.admin_feedback FROM assignment_submissions s
                 WHERE s.assignment_id = a.id AND s.student_id = ?
                 ORDER BY s.id DESC LIMIT 1) AS mentor_feedback,
                CASE WHEN a.due_date != '' AND ((length(a.due_date) = 10 AND a.due_date < date('now','localtime')) OR (length(a.due_date) > 10 AND datetime(replace(substr(a.due_date,1,16),'T',' ')) < datetime('now','localtime'))) THEN 1 ELSE 0 END AS deadline_passed
            FROM assignments a
            WHERE TRIM(a.batch) = ? OR a.batch = 'All'
            ORDER BY a.due_date ASC, a.id DESC
        """, (student_id, student_id, batch)).fetchall()

    content = """
    <h2>Assignments</h2>
    <p>Students submit their own work here. Mentors update the review status and feedback from the Review Submissions page.</p>
    {% for a in assignments %}
      <article class="item">
        <h3>{{ a['title'] }}</h3><p>{{ a['description'] }}</p>
        <p class="muted">Batch: {{ a['batch'] }} · Deadline: {{ (a['due_date']|replace('T', ' ')) if a['due_date'] else 'Not specified' }}</p>
        {% if a['attachment_name'] %}<p><a href="{{ url_for('download_assignment_attachment', assignment_id=a['id'], role='student') }}">Download instruction file: {{ a['attachment_name'] }}</a></p>{% endif %}
        <p>Status: <strong>{{ a['submission_status'] or 'Not Submitted' }}</strong></p>
        {% if a['mentor_feedback'] %}<p>Mentor feedback: {{ a['mentor_feedback'] }}</p>{% endif %}
        {% if a['deadline_passed'] %}
          <p class="muted"><strong>Deadline passed.</strong> This assignment remains visible, but submissions are closed.</p>
        {% elif a['submission_status'] not in ['Pending Review', 'Approved'] %}
          <form method="post" enctype="multipart/form-data">
            <input type="hidden" name="assignment_id" value="{{ a['id'] }}">
            <label>Upload your assignment (maximum 2 MB)</label><input type="file" name="submission_file" accept=".pdf,.doc,.docx,.txt,.zip,.jpg,.jpeg,.png" required>
            <p class="muted">Allowed: PDF, DOC, DOCX, TXT, ZIP, JPG or PNG. Maximum file size: 2 MB.</p>
            <p style="margin-top:10px"><button type="submit">Submit Assignment</button></p>
          </form>
        {% else %}
          <p class="muted">Submission saved. You cannot replace it unless your mentor requests a resubmission.</p>
        {% endif %}
      </article>
    {% else %}<p>No assignments are available for your batch.</p>{% endfor %}
    <p style="margin-top:18px"><a class="btn" href="{{ url_for('student_submissions') }}">View My Submissions</a></p>
    """
    return student_shell("My Assignments", render_template_string(content, assignments=assignments))
#-------------------------STUDENT PROFILE----------------------------


@app.route("/student/profile", methods=["GET", "POST"])
@student_required
def student_profile():
    """Allow a student to edit their own permitted profile fields."""

    student_id = session.get("student_id")

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        mobile = request.form.get("mobile", "").strip()
        address = request.form.get("address", "").strip()

        if not name or not email:
            flash("Name and email are required.", "error")
            return redirect(url_for("student_profile"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("student_profile"))

        if mobile and not re.fullmatch(r"[6-9]\d{9}", mobile):
            flash(
                "Enter a valid 10-digit Indian mobile number or leave it blank.",
                "error"
            )
            return redirect(url_for("student_profile"))

        try:
            with get_db() as db:

                current_student = db.execute(
                    """
                    SELECT student_id
                    FROM students
                    WHERE student_id = ?
                    """,
                    (student_id,)
                ).fetchone()

                if not current_student:
                    session.clear()
                    flash(
                        "Student record not found. Please log in again.",
                        "error"
                    )
                    return redirect(url_for("login"))

                email_owner = db.execute(
                    """
                    SELECT student_id
                    FROM students
                    WHERE lower(email) = lower(?)
                      AND student_id != ?
                    """,
                    (email, student_id)
                ).fetchone()

                if email_owner:
                    flash(
                        "That email address is already used by another student.",
                        "error"
                    )
                    return redirect(url_for("student_profile"))

                db.execute(
                    """
                    UPDATE students
                    SET name = ?, email = ?, mobile = ?, address = ?
                    WHERE student_id = ?
                    """,
                    (name, email, mobile or None, address, student_id)
                )

            # Refresh session display values.
            session["student_name"] = name
            session["student_email"] = email
            session["name"] = name
            session["email"] = email

            flash(
                "Your profile has been updated successfully.",
                "success"
            )
            return redirect(url_for("student_profile"))

        except sqlite3.IntegrityError:
            flash(
                "That email address is already in use. Please use another email.",
                "error"
            )
            return redirect(url_for("student_profile"))

    with get_db() as db:
        student = db.execute(
            """
            SELECT student_id, name, email, mobile, college,
                   course, batch, address, created_at
            FROM students
            WHERE student_id = ?
            """,
            (student_id,)
        ).fetchone()

    if not student:
        session.clear()
        flash("Student record not found. Please log in again.", "error")
        return redirect(url_for("login"))

    return student_shell(
        "My Profile",
        render_template("student_profile.html", student=student)
    )

#-------------------------------CHANGE PASSWORD--------------------

@app.route("/student/change-password", methods=["POST"])
@student_required
def student_change_password():
    """Change the logged-in student's password after checking the current password."""
    student_id = session.get("student_id")
    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    if not current_password or not new_password or not confirm_password:
        flash("Complete all password fields.", "error")
        return redirect(url_for("student_profile"))

    if len(new_password) < 8:
        flash("Your new password must contain at least 8 characters.", "error")
        return redirect(url_for("student_profile"))

    if new_password != confirm_password:
        flash("The new passwords do not match.", "error")
        return redirect(url_for("student_profile"))

    with get_db() as db:
        student = db.execute(
            "SELECT password_hash FROM students WHERE student_id = ?",
            (student_id,)
        ).fetchone()

        if not student:
            session.clear()
            flash("Student record not found. Please log in again.", "error")
            return redirect(url_for("login"))

        if not check_password_hash(student["password_hash"], current_password):
            flash("Your current password is incorrect.", "error")
            return redirect(url_for("student_profile"))

        db.execute(
            "UPDATE students SET password_hash = ? WHERE student_id = ?",
            (generate_password_hash(new_password), student_id)
        )

    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("student_profile"))

#-------------------STUDENT ANNOUNCEMENT----------------------

@app.route("/student/announcements")
@student_required
def student_announcements():
    """Show announcements published by the administrator."""
    with get_db() as db:
        rows = db.execute(
            "SELECT * FROM announcements ORDER BY id DESC"
        ).fetchall()

    content = """
    <h2>Announcements</h2>
    {% for item in rows %}
      <article class="item">
        <h3>{{ item['title'] }}</h3>
        <p>{{ item['message'] }}</p>
        <p class="muted">{{ item['created_at'] }}</p>
      </article>
    {% else %}
      <p>No announcements available right now.</p>
    {% endfor %}
    """
    return student_shell(
        "Announcements",
        render_template_string(content, rows=rows)
    )


@app.route("/student/calendar")
@student_required
def student_calendar():
    """Show assignment due dates for the logged-in student's batch."""
    student_id = session["student_id"]
    with get_db() as db:
        student = db.execute(
            "SELECT batch FROM students WHERE student_id = ?",
            (student_id,)
        ).fetchone()
        batch = (student["batch"] or "").strip() if student else ""
        rows = db.execute("""
            SELECT title, due_date, batch
            FROM assignments
            WHERE batch = ? OR batch = 'All'
            ORDER BY due_date ASC, id DESC
        """, (batch,)).fetchall()

    content = """
    <h2>Assignment Calendar</h2>
    <p>Upcoming due dates for assignments assigned to your batch.</p>
    {% for item in rows %}
      <article class="item">
        <h3>{{ item['title'] }}</h3>
        <p class="muted">Due date: {{ item['due_date'] or 'Not specified' }}</p>
        <p class="muted">Batch: {{ item['batch'] }}</p>
      </article>
    {% else %}
      <p>No assignment dates are available for your batch.</p>
    {% endfor %}
    """
    return student_shell(
        "Calendar",
        render_template_string(content, rows=rows)
    )


@app.route("/student/submissions")
@student_required
def student_submissions():
    with get_db() as db:
        rows = db.execute("""
            SELECT s.*,a.title FROM assignment_submissions s JOIN assignments a ON a.id=s.assignment_id
            WHERE s.student_id=? ORDER BY s.id DESC
        """, (session["student_id"],)).fetchall()
    content = "<h2>My Submissions</h2>"
    for row in rows:
        content += (f"<article class='item'><h3>{row['title']}</h3><p>File: {row['file_name']}</p>"
                    f"<p>Status: {row['status']}</p><p>Feedback: {row['admin_feedback'] or 'No feedback yet'}</p>"
                    f"<p class='muted'>Submitted: {row['submitted_at']}</p></article>")
    if not rows:
        content += "<p>You have not submitted any assignments yet.</p>"
    return student_shell("My Submissions", content)


# -------------------- STUDENT LEAVE / ATTENDANCE --------------------

@app.route("/student/leave", methods=["GET", "POST"])
@student_required
def student_leave():
    sid = session["student_id"]
    if request.method == "POST":
        start = request.form.get("start_date", "").strip()
        end = request.form.get("end_date", "").strip()
        reason = request.form.get("reason", "").strip()
        if not start or not end or not reason:
            flash("Complete all leave request fields.", "error")
        elif end < start:
            flash("End date cannot be before start date.", "error")
        else:
            with get_db() as db:
                db.execute("INSERT INTO leave_requests(student_id,start_date,end_date,reason) VALUES(?,?,?,?)",
                           (sid, start, end, reason))
                db.execute("INSERT INTO student_notifications(student_id,message) VALUES(?,?)",
                           (sid, "Your leave request was submitted for admin approval."))
            flash("Leave request submitted.", "success")
        return redirect(url_for("student_leave"))
    with get_db() as db:
        rows = db.execute("SELECT * FROM leave_requests WHERE student_id=? ORDER BY id DESC", (sid,)).fetchall()
    content = """
    <h2>Request Leave</h2><form method="post"><label>Start Date</label><input type="date" name="start_date" required>
    <label>End Date</label><input type="date" name="end_date" required><label>Reason</label>
    <textarea name="reason" rows="4" required></textarea><button type="submit">Send Leave Request</button></form>
    <h2 style="margin-top:25px">My Leave Requests</h2>
    {% for r in rows %}<article class="item"><p>{{ r['start_date'] }} to {{ r['end_date'] }}</p><p>{{ r['reason'] }}</p>
    <p>Status: {{ r['status'] }} | Feedback: {{ r['admin_feedback'] or 'None' }}</p></article>{% else %}<p>No requests yet.</p>{% endfor %}
    """
    return student_shell("Leave Requests", render_template_string(content, rows=rows))



@app.route("/student/attendance", methods=["GET", "POST"])
@student_required
def student_attendance():
    """Capture a camera snapshot and browser location; attendance waits for admin approval."""

    sid = session["student_id"]

    if request.method == "POST":

        day = request.form.get("attendance_date", "").strip()
        photo = request.form.get("camera_photo", "").strip()
        latitude = request.form.get("latitude", "").strip()
        longitude = request.form.get("longitude", "").strip()

        if (
            not day
            or not photo.startswith("data:image/")
            or not latitude
            or not longitude
        ):
            flash(
                "Allow camera and location access, capture your photo, and then submit attendance.",
                "error"
            )

        elif len(photo) > 3_000_000:
            flash(
                "Camera image is too large. Please capture again.",
                "error"
            )

        else:
            with get_db() as db:

                db.execute(
                    """
                    INSERT INTO attendance_requests
                    (
                        student_id,
                        attendance_date,
                        attendance_type,
                        reason,
                        status,
                        latitude,
                        longitude,
                        camera_photo
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        sid,
                        day,
                        "Present",
                        "Camera and location attendance",
                        "Pending",
                        latitude,
                        longitude,
                        photo
                    )
                )

                db.execute(
                    """
                    INSERT INTO student_notifications
                    (student_id, message)
                    VALUES (?, ?)
                    """,
                    (
                        sid,
                        f"Your attendance request for {day} was submitted with camera and location details and is awaiting admin approval."
                    )
                )

            flash(
                "Attendance request submitted. It will be counted after admin approval.",
                "success"
            )

        return redirect(url_for("student_attendance"))

    with get_db() as db:
        rows = db.execute(
            """
            SELECT *
            FROM attendance_requests
            WHERE student_id = ?
            ORDER BY attendance_date DESC, id DESC
            """,
            (sid,)
        ).fetchall()

    return student_shell(
        "Attendance",
        render_template(
            "student_attendance.html",
            rows=rows,
            today=datetime.now().strftime("%Y-%m-%d")
        )
    )


@app.route("/student/notifications")
@student_required
def student_notifications():
    with get_db() as db:
        rows = db.execute("SELECT * FROM student_notifications WHERE student_id=? ORDER BY id DESC",
                          (session["student_id"],)).fetchall()
        db.execute("UPDATE student_notifications SET is_read=1 WHERE student_id=?", (session["student_id"],))
    content = "<h2>Notifications</h2>"
    for row in rows:
        content += f"<article class='item'><p>{row['message']}</p><p class='muted'>{row['created_at']}</p></article>"
    if not rows:
        content += "<p>You have no notifications yet.</p>"
    return student_shell("Notifications", content)


# -------------------- MENTOR REVIEW / APPROVALS --------------------

@app.route("/admin/requests", methods=["GET", "POST"])
@admin_or_staff_required
def admin_requests():
    """Mentors review student uploads and can update status/feedback; students cannot access this route."""
    if request.method == "POST":
        kind = request.form.get("request_type", "")
        record_id = request.form.get("record_id", type=int)
        decision = request.form.get("decision", "")
        feedback = request.form.get("feedback", "").strip()
        allowed_decisions = {
            "submission": {"Pending Review", "Approved", "Rejected", "Resubmit Required"},
            "leave": {"Pending", "Approved", "Rejected"},
            "attendance": {"Pending", "Approved", "Rejected"},
        }
        tables = {
            "submission": "assignment_submissions",
            "leave": "leave_requests",
            "attendance": "attendance_requests",
        }
        if kind not in tables or decision not in allowed_decisions.get(kind, set()):
            flash("Invalid review details. Choose a valid status.", "error")
        else:
            if kind == "leave" and decision == "Approved" and (feedback.strip().lower().startswith("no") or feedback.strip().lower() in {"not approved", "not recommended"}):
                decision = "Rejected"
                if not feedback.strip():
                    feedback = "Your mentor has not recommended this leave. Please contact your mentor for clarification."
                elif "contact your mentor" not in feedback.lower() and "ask your mentor" not in feedback.lower():
                    feedback += " Please contact your mentor for clarification before applying again."
            table = tables[kind]
            with get_db() as db:
                record = db.execute(f"SELECT * FROM {table} WHERE id = ?", (record_id,)).fetchone()
                if not record:
                    flash("Request or submission not found.", "error")
                else:
                    db.execute(
                        f"UPDATE {table} SET status=?, admin_feedback=?, reviewed_at=CURRENT_TIMESTAMP WHERE id=?",
                        (decision, feedback, record_id)
                    )
                    message = f"Your {kind} status was updated to {decision}."
                    if kind == "leave" and decision == "Rejected" and feedback.strip().lower().startswith("no"):
                        message += " Please contact your mentor for clarification before applying again."
                    if feedback:
                        message += f" Mentor feedback: {feedback}"
                    db.execute(
                        "INSERT INTO student_notifications(student_id,message) VALUES(?,?)",
                        (record["student_id"], message)
                    )
                    flash("Review updated and student notified.", "success")
        return redirect(url_for("admin_requests"))

    with get_db() as db:
        submissions = db.execute("""
            SELECT s.*, a.title, st.name AS student_name
            FROM assignment_submissions s
            JOIN assignments a ON a.id = s.assignment_id
            LEFT JOIN students st ON st.student_id = s.student_id
            ORDER BY CASE WHEN s.status='Pending Review' THEN 0 ELSE 1 END, s.id DESC
        """).fetchall()
        leaves = db.execute("""
            SELECT l.*, st.name AS student_name FROM leave_requests l
            LEFT JOIN students st ON st.student_id = l.student_id ORDER BY l.id DESC
        """).fetchall()
        attendance = db.execute("""
            SELECT a.*, st.name AS student_name FROM attendance_requests a
            LEFT JOIN students st ON st.student_id = a.student_id ORDER BY a.id DESC
        """).fetchall()

    def review_form(kind, record):
        if kind == "submission":
            statuses = ("Pending Review", "Approved", "Rejected", "Resubmit Required")
        elif kind == "attendance":
            statuses = ("Pending", "Approved", "Rejected")
        else:
            statuses = ("Pending", "Approved", "Rejected")
        options = "".join(
            f'<option value="{status}" {"selected" if record["status"] == status else ""}>{status}</option>'
            for status in statuses
        )
        feedback = (record["admin_feedback"] or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
        return f"""<form method="post" class="review-form">
          <input type="hidden" name="request_type" value="{kind}">
          <input type="hidden" name="record_id" value="{record['id']}">
          <label>Mentor Feedback</label><textarea name="feedback" rows="2" maxlength="2000">{feedback}</textarea>
          <label>Review Status</label><select name="decision" required>{options}</select>
          <p style="margin-top:12px"><button type="submit">Save Review / Approval</button></p>
        </form>"""

    content = """
    <style>.review-form{background:#f8fafc;padding:14px;border-radius:9px;margin-top:12px}.file-link{display:inline-block;margin:8px 0;color:#173d70;font-weight:bold}</style>
    <h2>Student Assignment Submissions</h2>
    <p>Students submit files from their own accounts. Mentors can download each file, edit feedback, and approve, reject, or request a resubmission.</p>
    """
    for row in submissions:
        title = row["title"] or "Assignment"
        student_name = row["student_name"] or row["student_id"]
        content += f"""<article class="item"><h3>{title}</h3>
        <p><strong>Student:</strong> {student_name} ({row['student_id']})</p>
        <p><strong>File:</strong> {row['file_name']}</p>
        <p><strong>Submitted:</strong> {row['submitted_at']} · <strong>Status:</strong> {row['status']}</p>
        <a class="file-link" href="{url_for('download_submission', submission_id=row['id'])}">Download student submission</a>
        {review_form('submission', row)}</article>"""
    if not submissions:
        content += "<p>No student submissions yet.</p>"

    content += "<h2 style='margin-top:30px'>Leave Requests</h2>"
    for row in leaves:
        content += f"""<article class="item"><strong>{row['student_name'] or row['student_id']}</strong>
        <p>{row['start_date']} to {row['end_date']}</p><p>{row['reason']}</p><p>Status: {row['status']}</p>
        {review_form('leave', row)}</article>"""
    if not leaves:
        content += "<p>No leave requests.</p>"

    content += "<h2 style='margin-top:30px'>Camera & Location Attendance Approval</h2><p>Review the student's photo and reported location before approving attendance.</p>"
    for row in attendance:
        student_name = row['student_name'] or row['student_id']
        photo_html = f"<img src='{row['camera_photo']}' alt='Student attendance photo' style='max-width:220px;border-radius:10px'>" if row['camera_photo'] else "<p>No camera photo stored for this older record.</p>"
        location_html = f"<a target='_blank' rel='noopener' href='https://maps.google.com/?q={row['latitude']},{row['longitude']}'>View submitted location</a>" if row['latitude'] and row['longitude'] else "Location unavailable"
        content += f"""<article class='item'><strong>{student_name}</strong><p>Student ID: {row['student_id']}</p><p>{row['attendance_date']} · {row['attendance_type']} · Status: {row['status']}</p>{photo_html}<p>{location_html}</p>{review_form('attendance', row)}</article>"""
    if not attendance:
        content += "<p>No attendance records yet.</p>"

    role_title = "Mentor Review & Approvals" if (
        session.get("technical_logged_in") is True or session.get("nontechnical_logged_in") is True
    ) else "Admin Approvals"
    return admin_shell(role_title, content)


# -------------------- ADMIN REPORTS --------------------

@app.route("/admin/reports")
@admin_or_staff_required
def admin_reports():
    with get_db() as db:
        total_students = db.execute(
            "SELECT COUNT(*) FROM students"
        ).fetchone()[0]

        total_batches = db.execute(
            "SELECT COUNT(*) FROM batches"
        ).fetchone()[0]

        total_assignments = db.execute(
            "SELECT COUNT(*) FROM assignments"
        ).fetchone()[0]

        total_submissions = db.execute(
            "SELECT COUNT(*) FROM assignment_submissions"
        ).fetchone()[0]

        pending_submissions = db.execute(
            "SELECT COUNT(*) FROM assignment_submissions "
            "WHERE status = 'Pending Review'"
        ).fetchone()[0]

        pending_leaves = db.execute(
            "SELECT COUNT(*) FROM leave_requests "
            "WHERE status = 'Pending'"
        ).fetchone()[0]

        total_attendance = db.execute(
            "SELECT COUNT(*) FROM attendance_requests"
        ).fetchone()[0]

    content = f"""
    <h2>Reports</h2>
    <p>Current KreoPugo Flow Tracker statistics.</p>

    <div class="report-grid">
    <article class="item report-card">
        <h3>Total Students</h3>
        <p>{total_students}</p>
    </article>

    <article class="item report-card">
        <h3>Total Batches</h3>
        <p>{total_batches}</p>
    </article>

    <article class="item report-card">
        <h3>Total Assignments</h3>
        <p>{total_assignments}</p>
    </article>

    <article class="item report-card">
        <h3>Total Submissions</h3>
        <p>{total_submissions}</p>
    </article>

    <article class="item report-card">
        <h3>Pending Assignment Reviews</h3>
        <p>{pending_submissions}</p>
    </article>

    <article class="item report-card">
        <h3>Pending Leave Requests</h3>
        <p>{pending_leaves}</p>
    </article>

    <article class="item report-card">
        <h3>Total Attendance Records</h3>
        <p>{total_attendance}</p>
    </article>
    </div>
    """

    content = content.replace("<h2>Reports</h2>", "<h2>Reports</h2>")
    content = content.replace("<p>Current KreoPugo Flow Tracker statistics.</p>", "<p class='report-intro'>Current KreoPugo Flow Tracker statistics.</p><style>.report-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:16px}.report-card{margin:0;min-height:100px;padding:16px 18px}.report-card h3{margin:0 0 10px;color:#173D70;font-size:15px}.report-card p{font-size:23px;font-weight:700;color:#781E12;margin:0}.report-intro{margin:8px 0 16px;color:#6B7280}@media(max-width:620px){.report-grid{grid-template-columns:1fr}}</style>")
    return admin_shell("Reports", content)


# Allow both URL styles for the existing Approvals page.
app.add_url_rule(
    "/admin/approvals",
    endpoint="admin_approvals",
    view_func=admin_requests,
    methods=["GET", "POST"]
)

# Mentor-facing route for the same protected review/approval page.
app.add_url_rule(
    "/mentor/reviews", endpoint="mentor_reviews",
    view_func=admin_requests, methods=["GET", "POST"]
)


# -------------------- BATCH-WISE ASSIGNMENTS / LEAVES / SUBMISSIONS --------------------
@app.route("/admin/batch-activity", methods=["GET"])
@admin_or_staff_required
def admin_batch_activity():
    """Compact batch dashboard: students, progress, assignments, leaves and attendance."""
    selected_batch = request.args.get("batch", "").strip()
    with get_db() as db:
        batches = db.execute("""
            SELECT b.batch_name,
                   (SELECT COUNT(*) FROM students st WHERE LOWER(TRIM(COALESCE(st.batch,'')))=LOWER(TRIM(b.batch_name))) AS student_count,
                   (SELECT COUNT(*) FROM assignments a WHERE LOWER(TRIM(COALESCE(a.batch,''))) IN (LOWER(TRIM(b.batch_name)), 'all')) AS assignment_count
            FROM batches b ORDER BY b.batch_name COLLATE NOCASE
        """).fetchall()
        valid_names = {str(r['batch_name']).strip().casefold(): str(r['batch_name']).strip() for r in batches}
        if selected_batch:
            selected_batch = valid_names.get(selected_batch.casefold(), "")

        batch_students = []
        assignments = submissions = leaves = attendance = []
        student_count = 0
        if selected_batch:
            batch_students = db.execute("""
                SELECT st.student_id, st.name, st.email, st.mobile, st.college, st.course, st.batch, st.created_at,
                    (SELECT COUNT(*) FROM assignments a WHERE LOWER(TRIM(COALESCE(a.batch,''))) IN (LOWER(?), 'all')) AS assigned_count,
                    (SELECT COUNT(*) FROM assignment_submissions sub WHERE sub.student_id=st.student_id) AS submitted_count,
                    (SELECT COUNT(*) FROM leave_requests l WHERE l.student_id=st.student_id) AS leave_count,
                    (SELECT COUNT(*) FROM attendance_requests ar WHERE ar.student_id=st.student_id) AS attendance_count,
                    (SELECT COUNT(*) FROM attendance_requests ar WHERE ar.student_id=st.student_id AND LOWER(ar.attendance_type)='present' AND LOWER(ar.status) IN ('approved','present','accepted')) AS present_count
                FROM students st WHERE LOWER(TRIM(COALESCE(st.batch,'')))=LOWER(?)
                ORDER BY st.name COLLATE NOCASE
            """, (selected_batch, selected_batch)).fetchall()
            student_count = len(batch_students)
            assignments = db.execute("""
                SELECT a.id,a.title,a.description,a.batch,a.due_date,a.created_at,
                    (SELECT COUNT(*) FROM assignment_submissions sub WHERE sub.assignment_id=a.id) AS submission_count
                FROM assignments a WHERE LOWER(TRIM(COALESCE(a.batch,''))) IN (LOWER(?),'all')
                ORDER BY a.due_date,a.id DESC
            """, (selected_batch,)).fetchall()
            submissions = db.execute("""
                SELECT sub.id,sub.student_id,sub.file_name,sub.status,sub.admin_feedback,sub.submitted_at,
                    a.title,st.name AS student_name
                FROM assignment_submissions sub
                LEFT JOIN assignments a ON a.id=sub.assignment_id
                LEFT JOIN students st ON st.student_id=sub.student_id
                WHERE LOWER(TRIM(COALESCE(st.batch,'')))=LOWER(?)
                ORDER BY sub.id DESC
            """, (selected_batch,)).fetchall()
            leaves = db.execute("""
                SELECT l.id,l.student_id,l.start_date,l.end_date,l.reason,l.status,l.admin_feedback,l.created_at,
                    st.name AS student_name
                FROM leave_requests l LEFT JOIN students st ON st.student_id=l.student_id
                WHERE LOWER(TRIM(COALESCE(st.batch,'')))=LOWER(?) ORDER BY l.id DESC
            """, (selected_batch,)).fetchall()
            attendance = db.execute("""
                SELECT ar.id,ar.student_id,ar.attendance_date,ar.attendance_type,ar.reason,ar.status,
                    ar.admin_feedback,ar.created_at,st.name AS student_name
                FROM attendance_requests ar LEFT JOIN students st ON st.student_id=ar.student_id
                WHERE LOWER(TRIM(COALESCE(st.batch,'')))=LOWER(?) ORDER BY ar.attendance_date DESC,ar.id DESC
            """, (selected_batch,)).fetchall()

    return render_template(
        "admin_batch_activity.html",
        batches=batches, selected_batch=selected_batch,
        student_count=student_count, batch_students=batch_students,
        assignments=assignments, submissions=submissions,
        leaves=leaves, attendance=attendance
    )

# -------------------- LOGOUT / STARTUP --------------------

@app.after_request
def prevent_dashboard_cache(response):
    # Avoid stale dashboard pages reappearing from browser history after role changes.
    if request.path.startswith(("/admin", "/student", "/technical", "/nontechnical", "/dashboard")):
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response


@app.route("/logout")
def logout():
    session.clear()
    response = redirect(url_for("login"))
    # /logout is shared by every role, so explicitly remove all role cookies.
    for cookie_name in (
        "kp_login_session", "kp_admin_session", "kp_student_session",
        "kp_technical_session", "kp_nontechnical_session",
    ):
        response.delete_cookie(cookie_name, path="/")
    return response


try:
    init_db()
except Exception as _e:
    print(f"init_db note: {_e}")

if __name__ == "__main__":
    app.run(debug=True)
