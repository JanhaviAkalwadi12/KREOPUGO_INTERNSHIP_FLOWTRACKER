"""
KreoPugo data reset utility.

Run this file from the same folder as app.py and kreopugo_signup.db:
    python reset_kreopugo_data.py

It keeps app.py, templates, static assets, and the configured admin/staff
login credentials unchanged. It first makes a timestamped database backup.
"""

import os
import shutil
import sqlite3
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "kreopugo_signup.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "student_uploads")

# Delete dependent/user-entered data first. The admin login in this app.py
# is configured separately and is not stored in these tables.
TABLES_TO_CLEAR = [
    "assignment_submissions",
    "student_notifications",
    "leave_requests",
    "attendance_requests",
    "announcements",
    "assignments",
    "batches",
    "students",
]

def main():
    if not os.path.isfile(DB_PATH):
        print(f"Database not found: {DB_PATH}")
        print("Place this script in the same folder as kreopugo_signup.db.")
        return

    print("This will permanently clear KreoPugo students, batches, assignments,")
    print("submissions, attendance, leave requests, announcements, notifications,")
    print("and their uploaded files.")
    print("Your app.py, HTML, CSS, JavaScript, static assets and admin login")
    print("configuration will not be changed.")
    confirm = input('\nType ERASE KREOPUGO DATA to continue: ').strip()
    if confirm != "ERASE KREOPUGO DATA":
        print("Cancelled. No data was changed.")
        return

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BASE_DIR, f"kreopugo_signup_backup_{stamp}.db")

    # Make a consistent SQLite backup before any deletion.
    source = sqlite3.connect(DB_PATH)
    backup = sqlite3.connect(backup_path)
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()

    conn = sqlite3.connect(DB_PATH)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        existing = {
            row[0] for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )
        }
        conn.execute("BEGIN")
        for table in TABLES_TO_CLEAR:
            if table in existing:
                # Table names come only from the fixed allow-list above.
                conn.execute(f'DELETE FROM "{table}"')

        # Reset auto-increment IDs for the cleared tables.
        if "sqlite_sequence" in existing:
            placeholders = ",".join("?" for _ in TABLES_TO_CLEAR)
            conn.execute(
                f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                TABLES_TO_CLEAR,
            )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    # Remove uploaded assignment briefs, submissions and attendance photos.
    # The directory itself is retained because the app expects it to exist.
    if os.path.isdir(UPLOAD_DIR):
        for entry in os.listdir(UPLOAD_DIR):
            path = os.path.join(UPLOAD_DIR, entry)
            if os.path.isfile(path) or os.path.islink(path):
                os.remove(path)
            elif os.path.isdir(path):
                shutil.rmtree(path)

    print("\nKreoPugo data reset completed.")
    print(f"Database backup saved as: {backup_path}")
    print("Your website code and design files were not changed.")
    print("Restart the Flask app and sign in with your existing admin credentials.")

if __name__ == "__main__":
    main()
