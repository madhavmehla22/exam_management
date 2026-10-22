# ExamHub – Exam Management System (Flask + SQLite)

## Run
```
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
export FLASK_APP=app.py SECRET_KEY="$(python -c 'import secrets;print(secrets.token_hex(32))')"
export ADMIN_PASSWORD='choose-a-strong-one'          # optional; otherwise one is generated and printed once
flask init-db        # creates tables, departments and the admin account
flask seed-demo      # OPTIONAL, development only: DEMONSTRATION DATA; prints random one-time passwords
flask run
```
Open http://127.0.0.1:5000. No passwords are hardcoded; accounts created in the UI get a random temporary password shown once.

## Roles
- **Admin**: students, faculty (+subject assignment), subjects, exams (conflict detection), timetable, marks, publish results, reports/CSV.
- **Faculty**: own subjects/exams, marks entry only for exams of assigned subjects (checked on the server).
- **Student**: profile, timetable, own hall ticket, own published results (all queries are scoped to the logged-in user).

## Database (schema.sql)
`departments` 1—* `students`, `faculty`, `subjects`. `users` 1—1 `students`/`faculty` (login). `faculty` *—* `subjects` via `faculty_subjects`.
`subjects` 1—* `examinations` (room is a column on the exam). `marks` = one row per (exam, student). `results` = computed snapshot per (exam, student) created on publish. `activity_logs` = audit trail.

## Result rules
Marks >= subject passing marks → PASS; below → FAIL; marked absent → ABSENT (not passed, no percentage); no marks entered → INCOMPLETE. Marks are locked while results are published; unpublish to edit.

## Security
Werkzeug password hashing, session cookies (HttpOnly, SameSite), per-session CSRF token on every POST, role checks via decorator, parameterized SQL, CSV formula-injection guard, confirmation on destructive actions, audit log.
