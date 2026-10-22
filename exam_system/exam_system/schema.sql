PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS departments(id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL);
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK(role IN('admin','faculty','student')), active INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  student_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT, course TEXT NOT NULL,
  department_id INTEGER NOT NULL REFERENCES departments(id), semester INTEGER NOT NULL, enroll_year INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS faculty(id INTEGER PRIMARY KEY, user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
  faculty_id TEXT UNIQUE NOT NULL, name TEXT NOT NULL, email TEXT NOT NULL, phone TEXT,
  department_id INTEGER NOT NULL REFERENCES departments(id));
CREATE TABLE IF NOT EXISTS subjects(id INTEGER PRIMARY KEY, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  department_id INTEGER NOT NULL REFERENCES departments(id), semester INTEGER NOT NULL,
  max_marks INTEGER NOT NULL CHECK(max_marks>0), pass_marks INTEGER NOT NULL CHECK(pass_marks>=0 AND pass_marks<=max_marks));
CREATE TABLE IF NOT EXISTS faculty_subjects(faculty_id INTEGER REFERENCES faculty(id) ON DELETE CASCADE,
  subject_id INTEGER REFERENCES subjects(id) ON DELETE CASCADE, PRIMARY KEY(faculty_id,subject_id));
CREATE TABLE IF NOT EXISTS examinations(id INTEGER PRIMARY KEY, subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
  exam_date TEXT NOT NULL, start_time TEXT NOT NULL, duration INTEGER NOT NULL, max_marks INTEGER NOT NULL,
  room TEXT NOT NULL, status TEXT DEFAULT 'scheduled' CHECK(status IN('scheduled','cancelled')), published INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS marks(id INTEGER PRIMARY KEY, exam_id INTEGER NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, marks REAL, absent INTEGER DEFAULT 0,
  entered_by INTEGER REFERENCES users(id), updated_at TEXT, UNIQUE(exam_id,student_id));
CREATE TABLE IF NOT EXISTS results(id INTEGER PRIMARY KEY, exam_id INTEGER NOT NULL REFERENCES examinations(id) ON DELETE CASCADE,
  student_id INTEGER NOT NULL REFERENCES students(id) ON DELETE CASCADE, marks REAL, percentage REAL,
  status TEXT NOT NULL CHECK(status IN('PASS','FAIL','ABSENT','INCOMPLETE')), UNIQUE(exam_id,student_id));
CREATE TABLE IF NOT EXISTS activity_logs(id INTEGER PRIMARY KEY, user_id INTEGER, action TEXT NOT NULL, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE INDEX IF NOT EXISTS ix_students_dept ON students(department_id,semester);
CREATE INDEX IF NOT EXISTS ix_exam_date ON examinations(exam_date,room);
CREATE INDEX IF NOT EXISTS ix_marks_exam ON marks(exam_id);
