import os, re, csv, io, json, secrets, sqlite3, math
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, g, render_template, request, redirect, url_for, session, flash, abort, Response)
from werkzeug.security import generate_password_hash, check_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),  # set SECRET_KEY in production
    SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", PERMANENT_SESSION_LIFETIME=timedelta(hours=2))
DB = os.environ.get("DATABASE", os.path.join(BASE, "exam.db"))
COLLEGE = "Demo College of Engineering"
PER_PAGE = 8

def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB); g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db
@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d: d.close()
def q(sql, a=()): return db().execute(sql, a).fetchall()
def q1(sql, a=()): return db().execute(sql, a).fetchone()
def ex(sql, a=()): return db().execute(sql, a)
def log(action): ex("INSERT INTO activity_logs(user_id,action) VALUES(?,?)", (session.get("uid"), action))

# ---------- auth / csrf ----------
def login_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            if "uid" not in session: return redirect(url_for("login", next=request.path))
            if roles and session["role"] not in roles: abort(403)
            return f(*a, **k)
        return w
    return deco
@app.before_request
def csrf():
    if request.method == "POST":
        if not secrets.compare_digest(request.form.get("csrf", ""), session.get("csrf", "x")): abort(400, "Invalid CSRF token")
@app.context_processor
def ctx():
    session.setdefault("csrf", secrets.token_hex(16))
    return dict(csrf=session["csrf"], role=session.get("role"), uname=session.get("name"), COLLEGE=COLLEGE)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = q1("SELECT * FROM users WHERE username=? AND active=1", (request.form.get("username", "").strip(),))
        if u and check_password_hash(u["password_hash"], request.form.get("password", "")):
            session.clear(); session.permanent = True
            session.update(uid=u["id"], role=u["role"], name=u["username"], csrf=secrets.token_hex(16))
            return redirect(url_for("home"))
        flash("Invalid username or password.", "danger")
    return render_template("login.html")
@app.route("/logout", methods=["POST"])
def logout(): session.clear(); return redirect(url_for("login"))
@app.errorhandler(403)
def e403(e): return render_template("error.html", code=403, msg="You do not have access to this page."), 403
@app.errorhandler(404)
def e404(e): return render_template("error.html", code=404, msg="Page not found."), 404
@app.errorhandler(400)
def e400(e): return render_template("error.html", code=400, msg=getattr(e, "description", "Bad request")), 400

@app.route("/account", methods=["GET", "POST"])
@login_required()
def account():
    if request.method == "POST":
        u = q1("SELECT * FROM users WHERE id=?", (session["uid"],))
        new = request.form.get("new", "")
        if not check_password_hash(u["password_hash"], request.form.get("old", "")): flash("Current password is wrong.", "danger")
        elif len(new) < 8: flash("New password must be at least 8 characters.", "danger")
        else:
            ex("UPDATE users SET password_hash=? WHERE id=?", (generate_password_hash(new), u["id"])); log("Changed own password")
            db().commit(); flash("Password updated.", "success")
    return render_template("account.html")

# ---------- dashboards ----------
@app.route("/")
@login_required()
def home():
    r = session["role"]
    if r == "admin":
        s = {k: q1(f"SELECT COUNT(*) c FROM {t}")["c"] for k, t in [("Students", "students"), ("Faculty", "faculty"), ("Subjects", "subjects")]}
        s["Upcoming exams"] = q1("SELECT COUNT(*) c FROM examinations WHERE exam_date>=date('now') AND status='scheduled'")["c"]
        s["Published results"] = q1("SELECT COUNT(*) c FROM examinations WHERE published=1")["c"]
        subj = q("""SELECT s.code, ROUND(100.0*SUM(r.status='PASS')/COUNT(*),1) p FROM results r JOIN examinations e ON e.id=r.exam_id
                    JOIN subjects s ON s.id=e.subject_id GROUP BY s.id""")
        dist = q("SELECT status, COUNT(*) c FROM results GROUP BY status")
        perf = q("""SELECT d.name, ROUND(AVG(r.percentage),1) a FROM results r JOIN students st ON st.id=r.student_id
                    JOIN departments d ON d.id=st.department_id WHERE r.status IN('PASS','FAIL') GROUP BY d.id""")
        acts = q("SELECT a.action, a.created_at, u.username FROM activity_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 8")
        return render_template("dashboard_admin.html", s=s, subj=[dict(x) for x in subj], dist=[dict(x) for x in dist], perf=[dict(x) for x in perf], acts=acts)
    if r == "faculty":
        f = q1("SELECT * FROM faculty WHERE user_id=?", (session["uid"],))
        subs = q("SELECT s.* FROM subjects s JOIN faculty_subjects fs ON fs.subject_id=s.id WHERE fs.faculty_id=?", (f["id"],))
        exams = q("""SELECT e.*, s.code, s.name sname FROM examinations e JOIN subjects s ON s.id=e.subject_id
                     JOIN faculty_subjects fs ON fs.subject_id=s.id WHERE fs.faculty_id=? ORDER BY exam_date""", (f["id"],))
        return render_template("dashboard_faculty.html", f=f, subs=subs, exams=exams)
    st = me()
    subs = q("SELECT * FROM subjects WHERE department_id=? AND semester=?", (st["department_id"], st["semester"]))
    return render_template("dashboard_student.html", st=st, subs=subs, exams=student_exams(st))

def me(): 
    st = q1("SELECT s.*, d.name dept FROM students s JOIN departments d ON d.id=s.department_id WHERE user_id=?", (session["uid"],))
    if not st: abort(403)
    return st
def student_exams(st):
    return q("""SELECT e.*, s.code, s.name sname FROM examinations e JOIN subjects s ON s.id=e.subject_id
                WHERE s.department_id=? AND s.semester=? AND e.status='scheduled' ORDER BY exam_date, start_time""",
             (st["department_id"], st["semester"]))

# ---------- generic CRUD (admin) ----------
# field: (name, label, type, required)
E = {
 "students": dict(title="Students", table="students", search=["t.name", "t.student_id"], filters=["department_id", "semester"],
   sql="SELECT t.*, d.name department FROM students t JOIN departments d ON d.id=t.department_id",
   list=[("student_id", "ID"), ("name", "Name"), ("course", "Course"), ("department", "Department"), ("semester", "Sem")],
   fields=[("student_id", "Student ID", "text", 1), ("name", "Full name", "text", 1), ("email", "Email", "email", 1), ("phone", "Phone", "tel", 0),
           ("course", "Course", "text", 1), ("department_id", "Department", "dept", 1), ("semester", "Semester", "number", 1), ("enroll_year", "Enrollment year", "number", 1)]),
 "faculty": dict(title="Faculty", table="faculty", search=["t.name", "t.faculty_id"], filters=["department_id"],
   sql="SELECT t.*, d.name department, (SELECT GROUP_CONCAT(s.code,', ') FROM faculty_subjects fs JOIN subjects s ON s.id=fs.subject_id WHERE fs.faculty_id=t.id) subjects FROM faculty t JOIN departments d ON d.id=t.department_id",
   list=[("faculty_id", "ID"), ("name", "Name"), ("department", "Department"), ("subjects", "Assigned subjects")],
   fields=[("faculty_id", "Faculty ID", "text", 1), ("name", "Name", "text", 1), ("email", "Email", "email", 1), ("phone", "Phone", "tel", 0), ("department_id", "Department", "dept", 1)]),
 "subjects": dict(title="Subjects", table="subjects", search=["t.name", "t.code"], filters=["department_id", "semester"],
   sql="SELECT t.*, d.name department, (SELECT GROUP_CONCAT(f.name,', ') FROM faculty_subjects fs JOIN faculty f ON f.id=fs.faculty_id WHERE fs.subject_id=t.id) faculty FROM subjects t JOIN departments d ON d.id=t.department_id",
   list=[("code", "Code"), ("name", "Subject"), ("department", "Department"), ("semester", "Sem"), ("max_marks", "Max"), ("pass_marks", "Pass"), ("faculty", "Faculty")],
   fields=[("code", "Subject code", "text", 1), ("name", "Subject name", "text", 1), ("department_id", "Department", "dept", 1), ("semester", "Semester", "number", 1),
           ("max_marks", "Maximum marks", "number", 1), ("pass_marks", "Passing marks", "number", 1)]),
 "exams": dict(title="Examinations", table="examinations", search=["s.name", "s.code"], filters=["semester"],
   sql="SELECT t.*, s.code, s.name sname, s.semester, d.name department FROM examinations t JOIN subjects s ON s.id=t.subject_id JOIN departments d ON d.id=s.department_id",
   list=[("code", "Code"), ("sname", "Subject"), ("department", "Department"), ("exam_date", "Date"), ("start_time", "Start"), ("duration", "Mins"), ("room", "Room"), ("status", "Status")],
   fields=[("subject_id", "Subject", "subject", 1), ("exam_date", "Date", "date", 1), ("start_time", "Start time", "time", 1),
           ("duration", "Duration (minutes)", "number", 1), ("max_marks", "Maximum marks", "number", 1), ("room", "Room", "text", 1)]),
}
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

def clean(ent, form):
    d, errs = {}, []
    for n, label, t, req in E[ent]["fields"]:
        v = form.get(n, "").strip()
        if req and not v: errs.append(f"{label} is required."); continue
        if t == "email" and v and not EMAIL.match(v): errs.append("Enter a valid email.")
        if t == "tel" and v and not re.fullmatch(r"[0-9+\- ]{7,15}", v): errs.append("Enter a valid phone number.")
        if t in ("number", "dept", "subject") and v:
            if not v.isdigit(): errs.append(f"{label} must be a whole number."); continue
            v = int(v)
        d[n] = v
    if ent == "subjects" and not errs:
        if d["max_marks"] < 1 or d["pass_marks"] > d["max_marks"]: errs.append("Passing marks must be between 0 and maximum marks.")
    if ent == "students" and not errs and not (1 <= d["semester"] <= 12): errs.append("Semester must be 1-12.")
    if ent == "exams" and not errs: errs += exam_checks(d, form.get("id"))
    return d, errs

def exam_checks(d, eid):
    errs = []
    try:
        start = datetime.strptime(f'{d["exam_date"]} {d["start_time"]}', "%Y-%m-%d %H:%M")
    except ValueError: return ["Invalid date or time."]
    if d["duration"] < 15: errs.append("Duration must be at least 15 minutes.")
    end = start + timedelta(minutes=d["duration"])
    sub = q1("SELECT * FROM subjects WHERE id=?", (d["subject_id"],))
    if not sub: return ["Unknown subject."]
    if d["max_marks"] > sub["max_marks"]: errs.append("Exam maximum marks exceed the subject maximum.")
    for o in q("""SELECT e.*, s.department_id, s.semester, s.code FROM examinations e JOIN subjects s ON s.id=e.subject_id
                  WHERE e.exam_date=? AND e.status='scheduled' AND e.id!=?""", (d["exam_date"], eid or 0)):
        os_ = datetime.strptime(f'{o["exam_date"]} {o["start_time"]}', "%Y-%m-%d %H:%M"); oe = os_ + timedelta(minutes=o["duration"])
        if start < oe and os_ < end:
            if o["room"].lower() == d["room"].lower(): errs.append(f'Room {o["room"]} is already booked by {o["code"]} at that time.')
            if o["department_id"] == sub["department_id"] and o["semester"] == sub["semester"]:
                errs.append(f'Overlaps {o["code"]}, which the same student group must also attend.')
    return errs

def opts():
    return dict(depts=q("SELECT * FROM departments ORDER BY name"), subjects=q("SELECT id, code, name FROM subjects ORDER BY code"),
                fac_subjects=q("SELECT id, code, name FROM subjects ORDER BY code"))

@app.route("/manage/<ent>")
@login_required("admin")
def manage(ent):
    c = E.get(ent) or abort(404)
    where, a = [], []
    s = request.args.get("q", "").strip()
    if s: where.append("(" + " OR ".join(f"{x} LIKE ?" for x in c["search"]) + ")"); a += [f"%{s}%"] * len(c["search"])
    for f in c["filters"]:
        v = request.args.get(f, "")
        if v.isdigit():
            col = {"department_id": "t.department_id" if ent != "exams" else "s.department_id", "semester": "t.semester" if ent != "exams" else "s.semester"}[f]
            where.append(f"{col}=?"); a.append(int(v))
    w = (" WHERE " + " AND ".join(where)) if where else ""
    base = c["sql"] + w
    total = q1(f"SELECT COUNT(*) c FROM ({base})", a)["c"]
    page = max(1, request.args.get("page", 1, type=int))
    order = "t.exam_date DESC" if ent == "exams" else "t.id DESC"
    rows = q(f"{base} ORDER BY {order} LIMIT ? OFFSET ?", a + [PER_PAGE, (page - 1) * PER_PAGE])
    extra = {}
    if ent == "faculty":
        extra["assigned"] = {r["faculty_id"]: [x["subject_id"] for x in q("SELECT * FROM faculty_subjects")] for r in []}
        amap = {}
        for x in q("SELECT * FROM faculty_subjects"): amap.setdefault(x["faculty_id"], []).append(x["subject_id"])
        extra["assigned"] = amap
    return render_template("crud.html", ent=ent, c=c, rows=rows, page=page, pages=max(1, math.ceil(total / PER_PAGE)), total=total, args=request.args, **opts(), **extra)

@app.route("/manage/<ent>/save", methods=["POST"])
@login_required("admin")
def save(ent):
    c = E.get(ent) or abort(404)
    d, errs = clean(ent, request.form)
    eid = request.form.get("id", type=int)
    if errs:
        for e in errs: flash(e, "danger")
        return redirect(url_for("manage", ent=ent))
    try:
        cols = list(d)
        if eid:
            ex(f"UPDATE {c['table']} SET {','.join(k+'=?' for k in cols)} WHERE id=?", [d[k] for k in cols] + [eid]); log(f"Edited {ent} #{eid}"); msg = "Changes saved."
        else:
            if ent in ("students", "faculty"):
                uname = d["student_id" if ent == "students" else "faculty_id"]; pw = secrets.token_urlsafe(8)
                uid = ex("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (uname, generate_password_hash(pw), "student" if ent == "students" else "faculty")).lastrowid
                d["user_id"] = uid; cols = list(d); msg = f"Created. Temporary password for {uname}: {pw} (shown once)."
            else: msg = "Created."
            eid = ex(f"INSERT INTO {c['table']}({','.join(cols)}) VALUES({','.join('?'*len(cols))})", [d[k] for k in cols]).lastrowid
            log(f"Added {ent} #{eid}")
        if ent == "faculty":
            ex("DELETE FROM faculty_subjects WHERE faculty_id=?", (eid,))
            for sid in request.form.getlist("subjects"):
                if sid.isdigit(): ex("INSERT OR IGNORE INTO faculty_subjects VALUES(?,?)", (eid, int(sid)))
        db().commit(); flash(msg, "success")
    except sqlite3.IntegrityError:
        db().rollback(); flash("That ID/code already exists, or a linked record is missing.", "danger")
    return redirect(url_for("manage", ent=ent))

@app.route("/manage/<ent>/<int:i>/delete", methods=["POST"])
@login_required("admin")
def delete(ent, i):
    c = E.get(ent) or abort(404)
    row = q1(f"SELECT * FROM {c['table']} WHERE id=?", (i,)) or abort(404)
    if ent in ("students", "faculty"): ex("DELETE FROM users WHERE id=?", (row["user_id"],))
    ex(f"DELETE FROM {c['table']} WHERE id=?", (i,)); log(f"Deleted {ent} #{i}"); db().commit()
    flash("Deleted.", "success"); return redirect(url_for("manage", ent=ent))

@app.route("/exams/<int:i>/cancel", methods=["POST"])
@login_required("admin")
def cancel_exam(i):
    ex("UPDATE examinations SET status='cancelled' WHERE id=?", (i,)); log(f"Cancelled exam #{i}"); db().commit()
    flash("Examination cancelled.", "success"); return redirect(url_for("manage", ent="exams"))

# ---------- timetable ----------
@app.route("/timetable")
@login_required("admin", "student")
def timetable():
    if session["role"] == "student": return render_template("timetable.html", rows=student_exams(me()), depts=[], args={})
    where, a = ["t.status='scheduled'"], []
    for k, col in (("department_id", "s.department_id"), ("semester", "s.semester")):
        if request.args.get(k, "").isdigit(): where.append(f"{col}=?"); a.append(int(request.args[k]))
    rows = q(E["exams"]["sql"] + " WHERE " + " AND ".join(where) + " ORDER BY exam_date, start_time", a)
    return render_template("timetable.html", rows=rows, depts=q("SELECT * FROM departments"), args=request.args)

# ---------- marks ----------
def allowed_exams():
    if session["role"] == "admin":
        return q("SELECT e.*, s.code, s.name sname FROM examinations e JOIN subjects s ON s.id=e.subject_id WHERE e.status='scheduled' ORDER BY exam_date DESC")
    return q("""SELECT e.*, s.code, s.name sname FROM examinations e JOIN subjects s ON s.id=e.subject_id
                JOIN faculty_subjects fs ON fs.subject_id=s.id JOIN faculty f ON f.id=fs.faculty_id
                WHERE f.user_id=? AND e.status='scheduled' ORDER BY exam_date DESC""", (session["uid"],))

@app.route("/marks", methods=["GET", "POST"])
@login_required("admin", "faculty")
def marks():
    eid = request.values.get("exam", type=int)
    exams = allowed_exams(); cur = next((e for e in exams if e["id"] == eid), None)  # server-side authorization
    if eid and not cur: abort(403)
    if cur and cur["published"]: flash("Results are published; marks are locked.", "warning")
    students = []
    if cur:
        sub = q1("SELECT * FROM subjects WHERE id=?", (cur["subject_id"],))
        students = q("""SELECT st.id, st.student_id, st.name, m.marks, m.absent, m.updated_at FROM students st
                        LEFT JOIN marks m ON m.student_id=st.id AND m.exam_id=? WHERE st.department_id=? AND st.semester=?
                        AND (st.name LIKE ? OR st.student_id LIKE ?) ORDER BY st.student_id""",
                     (cur["id"], sub["department_id"], sub["semester"], f'%{request.args.get("q","")}%', f'%{request.args.get("q","")}%'))
        if request.method == "POST" and not cur["published"]:
            errs, now = [], datetime.now().strftime("%Y-%m-%d %H:%M")
            for s in students:
                v, ab = request.form.get(f"m{s['id']}", "").strip(), 1 if request.form.get(f"a{s['id']}") else 0
                if v == "" and not ab: continue
                try: val = None if ab else float(v)
                except ValueError: errs.append(f"{s['student_id']}: marks must be a number."); continue
                if val is not None and not (0 <= val <= cur["max_marks"]): errs.append(f"{s['student_id']}: marks must be 0-{cur['max_marks']}."); continue
                ex("""INSERT INTO marks(exam_id,student_id,marks,absent,entered_by,updated_at) VALUES(?,?,?,?,?,?)
                      ON CONFLICT(exam_id,student_id) DO UPDATE SET marks=excluded.marks, absent=excluded.absent, entered_by=excluded.entered_by, updated_at=excluded.updated_at""",
                   (cur["id"], s["id"], val, ab, session["uid"], now))
            if errs:
                db().rollback()
                for e in errs: flash(e, "danger")
            else: log(f"Saved marks for exam #{cur['id']}"); db().commit(); flash("Marks saved.", "success"); return redirect(url_for("marks", exam=cur["id"]))
    return render_template("marks.html", exams=exams, cur=cur, students=students)

# ---------- results ----------
def compute_results(eid):
    e = q1("SELECT e.*, s.pass_marks, s.department_id, s.semester FROM examinations e JOIN subjects s ON s.id=e.subject_id WHERE e.id=?", (eid,))
    ex("DELETE FROM results WHERE exam_id=?", (eid,))
    for st in q("SELECT st.id, m.marks, m.absent, m.id mid FROM students st LEFT JOIN marks m ON m.student_id=st.id AND m.exam_id=? WHERE st.department_id=? AND st.semester=?",
                (eid, e["department_id"], e["semester"])):
        if st["mid"] is None: status, pct = "INCOMPLETE", None          # no marks entered
        elif st["absent"]: status, pct = "ABSENT", None                  # absent counts as not passed
        else: pct = round(100 * st["marks"] / e["max_marks"], 2); status = "PASS" if st["marks"] >= e["pass_marks"] else "FAIL"
        ex("INSERT INTO results(exam_id,student_id,marks,percentage,status) VALUES(?,?,?,?,?)", (eid, st["id"], st["marks"], pct, status))

@app.route("/results")
@login_required("admin")
def results():
    rows = q("""SELECT e.*, s.code, s.name sname, (SELECT COUNT(*) FROM marks m WHERE m.exam_id=e.id) entered,
                (SELECT COUNT(*) FROM students st WHERE st.department_id=s.department_id AND st.semester=s.semester) total,
                (SELECT COUNT(*) FROM results r WHERE r.exam_id=e.id AND r.status='PASS') passed
                FROM examinations e JOIN subjects s ON s.id=e.subject_id WHERE e.status='scheduled' ORDER BY exam_date DESC""")
    return render_template("results.html", rows=rows)

@app.route("/results/<int:i>/<act>", methods=["POST"])
@login_required("admin")
def result_action(i, act):
    if act not in ("publish", "unpublish"): abort(404)
    if act == "publish": compute_results(i)
    ex("UPDATE examinations SET published=? WHERE id=?", (1 if act == "publish" else 0, i)); log(f"{act.title()}ed results for exam #{i}")
    db().commit(); flash(f"Results {act}ed.", "success"); return redirect(url_for("results"))

@app.route("/my-results")
@login_required("student")
def my_results():
    st = me()
    rows = q("""SELECT r.*, s.code, s.name sname, s.max_marks, s.pass_marks, e.max_marks emax FROM results r JOIN examinations e ON e.id=r.exam_id
                JOIN subjects s ON s.id=e.subject_id WHERE r.student_id=? AND e.published=1 ORDER BY s.semester, s.code""", (st["id"],))
    return render_template("my_results.html", st=st, rows=rows)

@app.route("/hallticket")
@login_required("student")
def hallticket():
    st = me(); return render_template("hallticket.html", st=st, exams=student_exams(st))

# ---------- reports ----------
REPORTS = {
 "subject-pass": ("Subject-wise pass percentage", """SELECT s.code, s.name, COUNT(*) appeared, SUM(r.status='PASS') passed,
    ROUND(100.0*SUM(r.status='PASS')/COUNT(*),1) pass_percent FROM results r JOIN examinations e ON e.id=r.exam_id JOIN subjects s ON s.id=e.subject_id
    WHERE r.status IN('PASS','FAIL') GROUP BY s.id"""),
 "department": ("Department-wise performance", """SELECT d.name department, COUNT(*) results, ROUND(AVG(r.percentage),1) avg_percentage,
    SUM(r.status='PASS') passed FROM results r JOIN students st ON st.id=r.student_id JOIN departments d ON d.id=st.department_id
    WHERE r.status IN('PASS','FAIL') GROUP BY d.id"""),
 "student": ("Student performance", """SELECT st.student_id, st.name, COUNT(*) subjects, ROUND(AVG(r.percentage),1) avg_percentage,
    SUM(r.status='PASS') passed FROM results r JOIN students st ON st.id=r.student_id GROUP BY st.id ORDER BY avg_percentage DESC"""),
 "participation": ("Examination participation", """SELECT s.code, e.exam_date, COUNT(*) eligible, SUM(r.status!='ABSENT' AND r.status!='INCOMPLETE') appeared,
    SUM(r.status='ABSENT') absent FROM results r JOIN examinations e ON e.id=r.exam_id JOIN subjects s ON s.id=e.subject_id GROUP BY e.id"""),
 "published": ("Published results summary", """SELECT s.code, s.name, e.exam_date, COUNT(r.id) results, SUM(r.status='PASS') passed, SUM(r.status='FAIL') failed
    FROM examinations e JOIN subjects s ON s.id=e.subject_id LEFT JOIN results r ON r.exam_id=e.id WHERE e.published=1 GROUP BY e.id"""),
}
@app.route("/reports")
@app.route("/reports/<key>")
@login_required("admin")
def reports(key="subject-pass"):
    title, sql = REPORTS.get(key) or abort(404)
    cur = db().execute(sql); cols = [c[0] for c in cur.description]
    return render_template("reports.html", key=key, title=title, cols=cols, rows=cur.fetchall(), REPORTS=REPORTS)
@app.route("/reports/<key>.csv")
@login_required("admin")
def report_csv(key):
    title, sql = REPORTS.get(key) or abort(404)
    cur = db().execute(sql); out = io.StringIO(); w = csv.writer(out); w.writerow([c[0] for c in cur.description])
    for r in cur: w.writerow([("'" + str(v)) if isinstance(v, str) and v[:1] in "=+-@" else v for v in r])  # block CSV formula injection
    log(f"Exported report {key}")
    db().commit(); return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": f"attachment; filename={key}.csv"})

# ---------- CLI ----------
def init_schema():
    c = sqlite3.connect(DB); c.executescript(open(os.path.join(BASE, "schema.sql")).read()); c.commit(); c.close()
@app.cli.command("init-db")
def init_db_cmd():
    """Create tables and an admin account. Set ADMIN_PASSWORD, or one is generated and printed once."""
    init_schema(); c = sqlite3.connect(DB)
    for d in ("Computer Science", "Electrical Engineering", "Mechanical Engineering"): c.execute("INSERT OR IGNORE INTO departments(name) VALUES(?)", (d,))
    pw = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(10)
    if c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone(): print("admin already exists")
    else:
        c.execute("INSERT INTO users(username,password_hash,role) VALUES('admin',?,'admin')", (generate_password_hash(pw),))
        print(f"Admin created. username: admin  password: {pw}")
    c.commit(); c.close()

@app.cli.command("seed-demo")
def seed_demo():
    """DEMONSTRATION DATA ONLY. Prints random one-time passwords."""
    init_schema(); c = sqlite3.connect(DB); c.execute("PRAGMA foreign_keys=ON"); c.row_factory = sqlite3.Row
    for d in ("Computer Science", "Electrical Engineering", "Mechanical Engineering"): c.execute("INSERT OR IGNORE INTO departments(name) VALUES(?)", (d,))
    dep = {r["name"]: r["id"] for r in c.execute("SELECT * FROM departments")}; cs = dep["Computer Science"]; ee = dep["Electrical Engineering"]
    def user(n, role):
        pw = secrets.token_urlsafe(6); print(f"{role:8} {n:10} {pw}")
        return c.execute("INSERT INTO users(username,password_hash,role) VALUES(?,?,?)", (n, generate_password_hash(pw), role)).lastrowid
    subs = [("CS301", "Data Structures", cs, 3, 100, 40), ("CS302", "Database Systems", cs, 3, 100, 40), ("CS303", "Operating Systems", cs, 3, 100, 40),
            ("EE301", "Circuit Theory", ee, 3, 100, 40), ("EE302", "Signals and Systems", ee, 3, 100, 40)]
    for s in subs: c.execute("INSERT OR IGNORE INTO subjects(code,name,department_id,semester,max_marks,pass_marks) VALUES(?,?,?,?,?,?)", s)
    sid = {r["code"]: r["id"] for r in c.execute("SELECT * FROM subjects")}
    for fid, n, dp, codes in [("F001", "Dr. Asha Rao", cs, ["CS301", "CS302"]), ("F002", "Prof. Mark Ellis", cs, ["CS303"]), ("F003", "Dr. Lena Park", ee, ["EE301", "EE302"])]:
        f = c.execute("INSERT INTO faculty(user_id,faculty_id,name,email,phone,department_id) VALUES(?,?,?,?,?,?)", (user(fid, "faculty"), fid, n, f"{fid.lower()}@demo.edu", "5550100", dp)).lastrowid
        for cd in codes: c.execute("INSERT INTO faculty_subjects VALUES(?,?)", (f, sid[cd]))
    names = ["Aarav Shah", "Maya Johnson", "Liam Chen", "Sofia Garcia", "Noah Kim", "Emma Davis", "Ravi Patel", "Zara Khan", "Ethan Brown", "Isha Verma"]
    for i, n in enumerate(names):
        k = f"S{2024001+i}"; dp = cs if i < 6 else ee
        c.execute("INSERT INTO students(user_id,student_id,name,email,phone,course,department_id,semester,enroll_year) VALUES(?,?,?,?,?,?,?,?,?)",
                  (user(k, "student"), k, n, f"{k.lower()}@demo.edu", "5550199", "B.Tech", dp, 3, 2024))
    for code, dt, room in [("CS301", "2026-11-10", "A-101"), ("CS302", "2026-11-12", "A-101"), ("CS303", "2026-11-14", "A-102"), ("EE301", "2026-11-10", "B-201"), ("EE302", "2026-11-12", "B-201")]:
        c.execute("INSERT INTO examinations(subject_id,exam_date,start_time,duration,max_blank,room) VALUES(?,?,?,?,?,?)".replace("max_blank", "max_marks"), (sid[code], dt, "10:00", 180, 100, room))
    c.commit(); c.close(); print("Demo data created (demonstration data only).")

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
