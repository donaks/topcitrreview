import csv
import io
import json
import secrets
from functools import wraps

from flask import Blueprint, Response, abort, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash


def question_fields(record, domains):
    if not isinstance(record, dict) or record.get('domain') not in tuple(domains):
        raise ValueError('Choose a domain from M1 through M4.')
    for key in ('stem', 'explanation'):
        if not isinstance(record.get(key), str) or not record[key].strip():
            raise ValueError(f'{key} must contain text.')
    options = record.get('options')
    if not isinstance(options, list) or len(options) != 4 or not all(isinstance(o, str) and o.strip() for o in options):
        raise ValueError('Provide four nonempty options.')
    answer = record.get('answer')
    if type(answer) is not int or answer not in range(4):
        raise ValueError('Use an answer index from 0 to 3.')
    fields = dict(domain=record['domain'], stem=record['stem'].strip(), explanation=record['explanation'].strip(),
                  options_json=json.dumps(options), answer=answer, status='draft')
    for key, default, limit in [('topic','General',120), ('difficulty','medium',20), ('source','Imported original item',255)]:
        value = record.get(key, default)
        if not isinstance(value, str) or len(value) > limit:
            raise ValueError(f'{key} must be text up to {limit} characters.')
        fields[key] = value
    return fields


def build_admin_portal(db, User, Question, Attempt, Audit, domains):
    portal = Blueprint('bank', __name__, url_prefix='/admin')

    def admin_required(view):
        @wraps(view)
        def protected(*args, **kwargs):
            uid = session.get('bank_admin')
            admin = db.session.get(User, uid) if uid else None
            if admin is None or admin.role != 'admin':
                session.pop('bank_admin', None)
                return redirect(url_for('bank.login'))
            return view(*args, **kwargs)
        return protected

    def log(action, details):
        db.session.add(Audit(user_id=session['bank_admin'], action=action, details=details))

    @portal.route('/login', methods=['GET', 'POST'])
    def login():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            user = User.query.filter_by(email=email, role='admin').first()
            if user and check_password_hash(user.password_hash, request.form.get('password', '')):
                session.clear()
                session.update(bank_admin=user.id, csrf=secrets.token_urlsafe(24))
                session.permanent = True
                return redirect(url_for('bank.admin'))
            flash('Invalid administrator credentials.')
        return render_template('admin_login.html')

    @portal.post('/logout')
    def logout():
        session.clear()
        return redirect(url_for('bank.login'))

    @portal.route('')
    @admin_required
    def admin():
     page = Question.query.order_by(Question.id.desc()).paginate(per_page=50)
     users = User.query.order_by(User.id.desc()).limit(150).all()
     return render_template('admin.html',questions=page.items,page=page,users=users)
    @portal.post('/question')
    @admin_required
    def question_add():
     try:
      opts=[request.form.get('o'+str(i),'').strip() for i in range(4)];answer=int(request.form.get('answer','-1'))
      if request.form.get('domain') not in domains or not all(opts) or answer not in range(4) or not request.form.get('stem','').strip() or not request.form.get('explanation','').strip():raise ValueError('Invalid question')
      q=Question(domain=request.form['domain'],topic=request.form.get('topic','General')[:120],difficulty=request.form.get('difficulty','medium'),stem=request.form['stem'].strip(),options_json=json.dumps(opts),answer=answer,explanation=request.form['explanation'].strip(),source='Original institutional item',status='draft');db.session.add(q);log('question_created',str(q.stem[:80]));db.session.commit();flash('Question created as draft')
     except (ValueError,KeyError):flash('Invalid question fields')
     return redirect(url_for('bank.admin'))
    @portal.post('/question/<int:qid>/status')
    @admin_required
    def question_status(qid):
     q=db.get_or_404(Question,qid);status=request.form.get('status')
     if status not in ('approved','draft','archived'):abort(400)
     q.status=status;log('question_status',f'{qid}: {status}');db.session.commit();return redirect(url_for('bank.admin'))
    @portal.post('/user/<int:uid>/role')
    @admin_required
    def user_role(uid):
     u=db.get_or_404(User,uid);role=request.form.get('role')
     if role not in ('student','instructor','admin'):abort(400)
     if u.id==session['bank_admin'] and role!='admin':abort(400,'Cannot demote yourself')
     u.role=role;log('role_change',f'{uid}: {role}');db.session.commit();return redirect(url_for('bank.admin'))
    @portal.post('/import')
    @admin_required
    def import_questions():
     upload = request.files.get('file')
     try:
      if not upload or not (upload.filename or '').lower().endswith('.json'):
       raise ValueError('Choose a JSON file.')
      records = json.load(upload)
      if not isinstance(records, list) or not 1 <= len(records) <= 1000:
       raise ValueError('Provide an array of 1 to 1000 questions.')
      staged = []
      for number, record in enumerate(records, 1):
       try:
        staged.append(Question(**question_fields(record, domains)))
       except ValueError as exc:
        raise ValueError(f'Question {number}: {exc}') from exc
      db.session.add_all(staged)
      log('question_import', str(len(staged)))
      db.session.commit()
      flash(f'Imported {len(staged)} draft questions.')
     except (ValueError, RecursionError) as exc:
      db.session.rollback()
      flash(f'Import rejected: {exc}')
     return redirect(url_for('bank.admin'))
    @portal.route('/export')
    @admin_required
    def export():
     output=io.StringIO();writer=csv.writer(output);writer.writerow(['id','domain','topic','difficulty','stem','status','correct_answer','explanation'])
     for q in Question.query.all():writer.writerow([q.id,q.domain,q.topic,q.difficulty,q.stem,q.status,q.options[q.answer],q.explanation])
     return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=questionbank.csv'})
    @portal.route('/report')
    @admin_required
    def report():
     rows=db.session.query(User.name,User.email,Attempt.mode,Attempt.score,Attempt.max_points,Attempt.submitted_at).join(Attempt,Attempt.user_id==User.id).filter(Attempt.submitted_at.isnot(None)).order_by(Attempt.id.desc()).all()
     output=io.StringIO();writer=csv.writer(output);writer.writerow(['name','email','mode','score','maximum','submitted_at']);writer.writerows(rows)
     return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=results.csv'})
    return portal

