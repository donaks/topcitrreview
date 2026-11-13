import os, json, csv, io, random, secrets
from datetime import datetime, timezone, timedelta
from functools import wraps
from flask import Flask, request, redirect, url_for, session, render_template, flash, Response, abort
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from werkzeug.security import generate_password_hash, check_password_hash
from verification import issue_code, accept_code
from dotenv import load_dotenv
load_dotenv()
app=Flask(__name__)
app.config.update(SECRET_KEY=os.environ['SECRET_KEY'],SQLALCHEMY_DATABASE_URI=os.getenv('DATABASE_URL','sqlite:///local_dev.db'),SQLALCHEMY_TRACK_MODIFICATIONS=False,SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax',SESSION_COOKIE_SECURE=os.getenv('SESSION_COOKIE_SECURE','0')=='1',PERMANENT_SESSION_LIFETIME=timedelta(hours=8),MAX_CONTENT_LENGTH=2*1024*1024)
db=SQLAlchemy(app)
DOMAINS={'M1':'Software Development','M2':'Data Management','M3':'Systems Architecture & Information Security','M4':'IT Business'}
WEIGHTS={'M1':365,'M2':265,'M3':235,'M4':135}
COUNTS={'M1':21,'M2':19,'M3':18,'M4':17}
def now():return datetime.now(timezone.utc)
class User(db.Model):
 id=db.Column(db.Integer,primary_key=True);email=db.Column(db.String(190),unique=True,nullable=False);name=db.Column(db.String(160),nullable=False);password_hash=db.Column(db.String(255),nullable=False);role=db.Column(db.String(20),nullable=False,default='student');created_at=db.Column(db.DateTime(timezone=True),default=now)
class EmailVerification(db.Model):
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    verified_at = db.Column(db.DateTime)
    signature = db.Column(db.String(64))
    sent_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)
    attempts = db.Column(db.Integer, nullable=False, default=0)

class Question(db.Model):
 id=db.Column(db.Integer,primary_key=True);domain=db.Column(db.String(2),nullable=False,index=True);topic=db.Column(db.String(120),nullable=False);difficulty=db.Column(db.String(20),default='medium');kind=db.Column(db.String(20),default='single');stem=db.Column(db.Text,nullable=False);options_json=db.Column(db.Text,nullable=False);answer=db.Column(db.Integer,nullable=False);explanation=db.Column(db.Text,nullable=False);source=db.Column(db.String(255),default='Original instructional item');status=db.Column(db.String(20),default='draft');created_at=db.Column(db.DateTime(timezone=True),default=now)
 @property
 def options(self):return json.loads(self.options_json)
class Attempt(db.Model):
 id=db.Column(db.Integer,primary_key=True);user_id=db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False);mode=db.Column(db.String(20),nullable=False);started_at=db.Column(db.DateTime(timezone=True),default=now);deadline=db.Column(db.DateTime(timezone=True),nullable=False);submitted_at=db.Column(db.DateTime(timezone=True));score=db.Column(db.Float);max_points=db.Column(db.Float);user=db.relationship('User')
class AttemptItem(db.Model):
 id=db.Column(db.Integer,primary_key=True);attempt_id=db.Column(db.Integer,db.ForeignKey('attempt.id'),nullable=False);question_id=db.Column(db.Integer,db.ForeignKey('question.id'),nullable=False);position=db.Column(db.Integer,nullable=False);points=db.Column(db.Float,nullable=False);selected=db.Column(db.Integer);question=db.relationship('Question')
class Audit(db.Model):
 id=db.Column(db.Integer,primary_key=True);user_id=db.Column(db.Integer);action=db.Column(db.String(100));details=db.Column(db.Text);created_at=db.Column(db.DateTime(timezone=True),default=now)
def current_user():return db.session.get(User,session.get('uid')) if session.get('uid') else None
@app.context_processor
def context():return dict(me=current_user(),domains=DOMAINS)
@app.before_request
def csrf_check():
 if request.method in ('POST','PUT','PATCH','DELETE') and (not session.get('csrf') or request.form.get('_csrf')!=session['csrf']):abort(400,'Invalid CSRF token')
 if 'csrf' not in session:session['csrf']=secrets.token_urlsafe(24)
@app.context_processor
def csrf():return dict(csrf=session.get('csrf',''))
def login_required(fn):
 @wraps(fn)
 def wrapper(*a,**k):
  if not current_user():return redirect(url_for('login'))
  return fn(*a,**k)
 return wrapper
def roles(*allowed):
 def deco(fn):
  @wraps(fn)
  @login_required
  def wrapper(*a,**k):
   if current_user().role not in allowed:abort(403)
   return fn(*a,**k)
  return wrapper
 return deco
def log(action,details=''):
 db.session.add(Audit(user_id=session.get('uid'),action=action,details=details))
@app.route('/')
def index():return render_template('index.html',total=Question.query.filter_by(status='approved').count(),users=User.query.count())
@app.route('/login',methods=['GET','POST'])
def login():
 if request.method=='POST':
  u=User.query.filter_by(email=request.form.get('email','').strip().lower()).first()
  if u and check_password_hash(u.password_hash,request.form.get('password','')):
   if u.role == 'student':
    verification = db.session.get(EmailVerification, u.id)
    if verification is None or verification.verified_at is None:
     session.clear()
     session['pending_student'] = u.id
     session['csrf'] = secrets.token_urlsafe(24)
     flash(issue_code(db, EmailVerification, u))
     return redirect(url_for('verify_email'))
   return start_session(u.id)
  flash('Invalid credentials')
 return render_template('login.html')
def start_session(user_id):
    session.clear()
    session['uid'] = user_id
    session['csrf'] = secrets.token_urlsafe(24)
    session.permanent = True
    return redirect(url_for('dashboard'))

@app.route('/verify-email', methods=['GET', 'POST'])
def verify_email():
    user_id = session.get('pending_student')
    user = db.session.get(User, user_id) if user_id else None
    if user is None or user.role != 'student':
        return redirect(url_for('login'))
    if request.method == 'POST':
        if request.form.get('action') == 'resend':
            flash(issue_code(db, EmailVerification, user))
        elif accept_code(db, EmailVerification, user_id, request.form.get('code', '').strip()):
            return start_session(user_id)
        else:
            flash('Invalid or expired code. Use the latest email or request another code.')
        return redirect(url_for('verify_email'))
    return render_template('verify_email.html', email=user.email)

@app.post('/logout')
def logout():session.clear();return redirect(url_for('index'))
@app.route('/register',methods=['GET','POST'])
def register():
 if request.method=='POST':
  email=request.form.get('email','').strip().lower();pw=request.form.get('password','');name=request.form.get('name','').strip()
  if len(pw)<12 or len(name)<2 or '@' not in email:flash('Provide a name, valid email and password of at least 12 characters')
  elif pw!=request.form.get('confirm_password'):flash('Passwords do not match')
  elif User.query.filter_by(email=email).first():flash('Email already registered')
  else:
   db.session.add(User(email=email,name=name,password_hash=generate_password_hash(pw),role='student'));db.session.commit();flash('Account created. Please sign in.');return redirect(url_for('login'))
 return render_template('register.html')
@app.route('/dashboard')
@login_required
def dashboard():
 attempts=Attempt.query.filter_by(user_id=current_user().id).order_by(Attempt.id.desc()).limit(20).all()
 return render_template('dashboard.html',attempts=attempts,counts={d:Question.query.filter_by(domain=d,status='approved').count() for d in DOMAINS})
@app.post('/start')
@login_required
def start():
 mode=request.form.get('mode','practice');domain=request.form.get('domain','ALL')
 if mode not in ('practice','mock') or domain not in (*DOMAINS,'ALL'):abort(400)
 if mode=='mock':
  selected=[]
  for d,n in COUNTS.items():
   pool=Question.query.filter_by(domain=d,status='approved').all()
   if len(pool)<n:flash('Not enough approved questions for a 75-item mock exam');return redirect(url_for('dashboard'))
   selected.extend((q,WEIGHTS[d]/n) for q in random.sample(pool,n))
  random.shuffle(selected);minutes=150
 else:
  pool=Question.query.filter_by(status='approved')
  if domain!='ALL':pool=pool.filter_by(domain=domain)
  pool=pool.all()
  if not pool:flash('No approved questions available');return redirect(url_for('dashboard'))
  selected=[(q,1) for q in random.sample(pool,min(10,len(pool)))];minutes=30
 a=Attempt(user_id=current_user().id,mode=mode,deadline=now()+timedelta(minutes=minutes),max_points=sum(points for q,points in selected));db.session.add(a);db.session.flush()
 for i,(q,pts) in enumerate(selected):db.session.add(AttemptItem(attempt_id=a.id,question_id=q.id,position=i,points=pts))
 db.session.commit();return redirect(url_for('exam',aid=a.id))
def get_attempt(aid):
 a=db.session.get(Attempt,aid)
 if not a:abort(404)
 if a.user_id!=current_user().id and current_user().role not in ('admin','instructor'):abort(403)
 return a
def finish(a):
 if a.submitted_at:return
 items=AttemptItem.query.filter_by(attempt_id=a.id).all();a.score=sum(i.points for i in items if i.selected==i.question.answer);a.submitted_at=now();db.session.commit()
@app.route('/exam/<int:aid>',methods=['GET','POST'])
@login_required
def exam(aid):
 a=get_attempt(aid)
 if a.user_id!=current_user().id:abort(403)
 if a.submitted_at:return redirect(url_for('result',aid=aid))
 if now()>a.deadline.replace(tzinfo=timezone.utc):finish(a);return redirect(url_for('result',aid=aid))
 items=AttemptItem.query.filter_by(attempt_id=aid).order_by(AttemptItem.position).all()
 if request.method=='POST':
  for item in items:
   value=request.form.get('q'+str(item.id),'')
   if value.isdigit() and 0<=int(value)<len(item.question.options):item.selected=int(value)
  db.session.commit()
  if request.form.get('submit')=='final':finish(a);return redirect(url_for('result',aid=aid))
  flash('Answers saved')
 return render_template('exam.html',attempt=a,items=items,deadline=a.deadline.replace(tzinfo=timezone.utc).isoformat())
@app.route('/result/<int:aid>')
@login_required
def result(aid):
 a=get_attempt(aid)
 if not a.submitted_at:
  if now()>a.deadline.replace(tzinfo=timezone.utc):finish(a)
  else:return redirect(url_for('exam',aid=aid))
 items=AttemptItem.query.filter_by(attempt_id=aid).order_by(AttemptItem.position).all()
 bydomain={d:{'earned':round(sum(i.points for i in items if i.question.domain==d and i.selected==i.question.answer),2),'possible':round(sum(i.points for i in items if i.question.domain==d),2)} for d in DOMAINS}
 return render_template('result.html',attempt=a,items=items,bydomain=bydomain)
@app.route('/admin')
@roles('admin','instructor')
def admin():
 qs=Question.query.order_by(Question.id.desc()).limit(150).all();users=User.query.order_by(User.id.desc()).limit(150).all()
 return render_template('admin.html',questions=qs,users=users)
@app.post('/admin/question')
@roles('admin','instructor')
def question_add():
 try:
  opts=[request.form.get('o'+str(i),'').strip() for i in range(4)];answer=int(request.form.get('answer','-1'))
  if request.form.get('domain') not in DOMAINS or not all(opts) or answer not in range(4) or not request.form.get('stem','').strip() or not request.form.get('explanation','').strip():raise ValueError('Invalid question')
  q=Question(domain=request.form['domain'],topic=request.form.get('topic','General')[:120],difficulty=request.form.get('difficulty','medium'),stem=request.form['stem'].strip(),options_json=json.dumps(opts),answer=answer,explanation=request.form['explanation'].strip(),source='Original institutional item',status='draft');db.session.add(q);log('question_created',str(q.stem[:80]));db.session.commit();flash('Question created as draft')
 except (ValueError,KeyError):flash('Invalid question fields')
 return redirect(url_for('admin'))
@app.post('/admin/question/<int:qid>/status')
@roles('admin')
def question_status(qid):
 q=db.get_or_404(Question,qid);status=request.form.get('status')
 if status not in ('approved','draft','archived'):abort(400)
 q.status=status;log('question_status',f'{qid}: {status}');db.session.commit();return redirect(url_for('admin'))
@app.post('/admin/user/<int:uid>/role')
@roles('admin')
def user_role(uid):
 u=db.get_or_404(User,uid);role=request.form.get('role')
 if role not in ('student','instructor','admin'):abort(400)
 if u.id==current_user().id and role!='admin':abort(400,'Cannot demote yourself')
 u.role=role;log('role_change',f'{uid}: {role}');db.session.commit();return redirect(url_for('admin'))
@app.post('/admin/import')
@roles('admin','instructor')
def import_questions():
 f=request.files.get('file')
 if not f or not f.filename.lower().endswith('.json'):abort(400,'JSON required')
 try:
  data=json.load(f);assert isinstance(data,list) and len(data)<=1000
  staged=[]
  for x in data:
   assert x['domain'] in DOMAINS and isinstance(x['options'],list) and len(x['options'])==4 and all(isinstance(y,str) and y.strip() for y in x['options']) and isinstance(x['answer'],int) and 0<=x['answer']<4 and x['stem'].strip() and x['explanation'].strip()
   staged.append(Question(domain=x['domain'],topic=str(x.get('topic','General'))[:120],difficulty=str(x.get('difficulty','medium'))[:20],stem=x['stem'],options_json=json.dumps(x['options']),answer=x['answer'],explanation=x['explanation'],source=str(x.get('source','Imported original item'))[:255],status='draft'))
  db.session.add_all(staged);log('question_import',str(len(staged)));db.session.commit();flash(f'Imported {len(staged)} draft questions; admin approval required')
 except (AssertionError,ValueError,KeyError,TypeError,UnicodeDecodeError,json.JSONDecodeError):db.session.rollback();flash('Import rejected: invalid JSON question format')
 return redirect(url_for('admin'))
@app.route('/admin/export')
@roles('admin','instructor')
def export():
 output=io.StringIO();writer=csv.writer(output);writer.writerow(['id','domain','topic','difficulty','stem','status','correct_answer','explanation'])
 for q in Question.query.all():writer.writerow([q.id,q.domain,q.topic,q.difficulty,q.stem,q.status,q.options[q.answer],q.explanation])
 return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=questionbank.csv'})
@app.route('/admin/report')
@roles('admin','instructor')
def report():
 rows=db.session.query(User.name,User.email,Attempt.mode,Attempt.score,Attempt.max_points,Attempt.submitted_at).join(Attempt,Attempt.user_id==User.id).filter(Attempt.submitted_at.isnot(None)).order_by(Attempt.id.desc()).all()
 output=io.StringIO();writer=csv.writer(output);writer.writerow(['name','email','mode','score','maximum','submitted_at']);writer.writerows(rows)
 return Response(output.getvalue(),mimetype='text/csv',headers={'Content-Disposition':'attachment; filename=results.csv'})
@app.cli.command('init-db')
def init_db():
 db.create_all();print('Tables created')
@app.cli.command('create-admin')
def create_admin():
 email=os.environ['ADMIN_EMAIL'].strip().lower();pw=os.environ['ADMIN_PASSWORD']
 if len(pw)<12:raise RuntimeError('Admin password must be at least 12 characters')
 u=User.query.filter_by(email=email).first()
 if not u:u=User(email=email,name='Administrator',password_hash=generate_password_hash(pw),role='admin');db.session.add(u)
 else:u.password_hash=generate_password_hash(pw);u.role='admin'
 db.session.commit();print('Admin created/updated')
@app.cli.command('seed')
def seed():
 with open(os.path.join(os.path.dirname(__file__),'questions.json'),encoding='utf8') as f:data=json.load(f)
 added=0
 for x in data:
  if Question.query.filter_by(stem=x['stem']).first():continue
  db.session.add(Question(domain=x['domain'],topic=x['topic'],difficulty=x['difficulty'],stem=x['stem'],options_json=json.dumps(x['options']),answer=x['answer'],explanation=x['explanation'],source=x['source'],status='approved'));added+=1
 db.session.commit();print(f'Inserted {added} original questions')
if __name__=='__main__':app.run(debug=False)
