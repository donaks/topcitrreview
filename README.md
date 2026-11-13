# TOPCIT ReviewBank — Flask + MySQL 8

Original institutional practice material; **not official TOPCIT questions**. This is a working MVP for a VPS, not a security-certified examination platform.

## Features
- 100 original single-answer MCQs, with explanations: M1=30, M2=27, M3=25, M4=18
- Student self-registration, login, role-based administrator/instructor/student access
- Domain-based practice: 10 questions, 30 minutes
- 75-question mock: M1 21, M2 19, M3 18, M4 17, 150 minutes; weighted to 1,000 points
- Server-enforced deadline, saved answers, result explanations, domain breakdown
- Admin approval for imported and manually entered draft questions; user roles; audit entries
- JSON import, question CSV export, results CSV export

## Ubuntu VPS installation (Ubuntu 22.04/24.04)

```bash
sudo apt update
sudo apt install -y python3-venv python3-pip mysql-server nginx
sudo mysql
```

Run in MySQL shell (replace the password):

```sql
CREATE DATABASE topcit_reviewbank CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'reviewbank'@'localhost' IDENTIFIED BY 'REPLACE_WITH_STRONG_DB_PASSWORD';
GRANT ALL PRIVILEGES ON topcit_reviewbank.* TO 'reviewbank'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

Copy this project to `/opt/topcit_reviewbank`, then:

```bash
cd /opt/topcit_reviewbank
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp .env.example .env
# Edit .env with real DATABASE_URL, SECRET_KEY, ADMIN_EMAIL and ADMIN_PASSWORD.
# Use a URL-encoded password in DATABASE_URL if it has reserved URL characters.
chmod 600 .env
.venv/bin/flask --app app init-db
.venv/bin/flask --app app create-admin
.venv/bin/flask --app app seed
.venv/bin/gunicorn --bind 127.0.0.1:8000 --workers 3 app:app
```

For background operation, install `deploy/topcit.service` to `/etc/systemd/system/topcit.service`, adjust User/Group and paths, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now topcit
sudo systemctl status topcit
```

Copy `deploy/nginx.conf` to `/etc/nginx/sites-available/topcit`, replace `YOUR_DOMAIN`, enable it, and reload Nginx. Use a DNS A record pointing to your VPS. Obtain TLS certificate:

```bash
sudo ln -s /etc/nginx/sites-available/topcit /etc/nginx/sites-enabled/topcit
sudo nginx -t && sudo systemctl reload nginx
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d YOUR_DOMAIN
```

Set `SESSION_COOKIE_SECURE=1` for HTTPS. Restrict firewall ports to SSH, 80 and 443; do not expose MySQL or Gunicorn publicly. Keep `.env` outside version control.

## Import format

`questions.json` provides an example list. JSON objects require `domain`, `stem`, `options` (four strings), `answer` (integer 0–3), `explanation`; optional `topic`, `difficulty`, `source`. Import creates **drafts**. Admin approves questions after review. `flask seed` inserts the bundled vetted-by-authoring (not independently expert-reviewed) questions as approved for demonstration; administrators should review them before real use.

## Data model

`user`: accounts and roles. `question`: domain, topic, answer key and explanation. `attempt`: exam timing and score. `attempt_item`: snapshot of assigned question IDs, answers and weights. `audit`: selected management events.

SQLAlchemy creates the MySQL schema through `flask init-db`. See `schema.sql` for a reference schema.

## Important limitations before high-stakes use

- This version supports single-answer MCQs only; not actual TOPCIT performance-based tasks, essay marking or coding evaluation.
- Answers are saved by explicit Save or Submit, **not automatically after every click**. Deadline is checked server-side when a request arrives; unanswered items are scored zero.
- A browser reload after timeout triggers scoring; scheduled finalization of abandoned attempts is not implemented.
- Questions are referenced live, not immutable snapshots; do not edit or remove used question records after an exam.
- No password-reset/email verification, per-IP rate limiting, account lockout, proctoring, or production-grade anti-cheating. Add before high-stakes deployment.
- Content is original but requires academic review. Domain weights are configurable constants based on the stated 2026 blueprint and should be rechecked with TOPCIT.
- For schema changes use migrations (e.g. Flask-Migrate); `create_all` does not alter existing tables.
- Exported CSV contains sensitive student information; restrict distribution and follow applicable privacy rules.

## Local development

For a quick test, omit DATABASE_URL to use SQLite locally, set `SESSION_COOKIE_SECURE=0`, then run init-db/create-admin/seed and `flask --app app run`. **MySQL is the recommended deployment database.**

## Student email verification

Set a random SECRET_KEY and configure SMTP_HOST, SMTP_PORT, SMTP_FROM,
SMTP_USERNAME and SMTP_PASSWORD in the application environment. Use a sender
authorized by your mail provider. Run Flask's init-db command before restarting
the application to create the email_verification table on an existing database.
Existing students verify at their next password login. Administrators and
instructors continue using their existing sign-in flow.
