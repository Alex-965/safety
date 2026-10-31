"""Lab 6. Loopback educational application. See README for deployment limits."""
import os, sqlite3, secrets, hashlib, time, io, json, smtplib
from pathlib import Path
from email.message import EmailMessage
from functools import wraps
from datetime import timedelta
from flask import Flask, request, session, redirect, url_for, render_template, abort, g, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from authlib.integrations.flask_client import OAuth
import pyotp
from PIL import Image, ImageDraw, ImageFont

def create_app(config=None):
    app = Flask(__name__, instance_relative_config=True)
    Path(app.instance_path).mkdir(exist_ok=True)
    def persistent(name, generator):
        p = Path(app.instance_path)/name
        if not p.exists(): p.write_bytes(generator())
        return p.read_bytes()
    app.config.update(SECRET_KEY=persistent('session.key',lambda:secrets.token_bytes(32)),
        DATABASE=str(Path(app.instance_path)/'accounts.db'), DEMO=True,
        FERNET_KEY=persistent('fernet.key',Fernet.generate_key),
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30), MAX_CONTENT_LENGTH=16384,
        OIDC_METADATA=os.getenv('OIDC_METADATA','http://127.0.0.1:5001/.well-known/openid-configuration'),
        OIDC_CLIENT_ID=os.getenv('OIDC_CLIENT_ID','lab-client'),
        OIDC_CLIENT_SECRET=os.getenv('OIDC_CLIENT_SECRET','local-demo-only'))
    if config: app.config.update(config)
    cipher=Fernet(app.config['FERNET_KEY'])
    oauth=OAuth(app)
    oauth.register('idp',server_metadata_url=app.config['OIDC_METADATA'],
        client_id=app.config['OIDC_CLIENT_ID'],client_secret=app.config['OIDC_CLIENT_SECRET'],
        client_kwargs={'scope':'openid email profile','code_challenge_method':'S256'})
    def db():
        if 'db' not in g:
            g.db=sqlite3.connect(app.config['DATABASE']); g.db.row_factory=sqlite3.Row
        return g.db
    @app.teardown_appcontext
    def close(_):
        conn=g.pop('db',None)
        if conn: conn.close()
    with app.app_context():
        db().executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,email TEXT UNIQUE,password TEXT,active INTEGER DEFAULT 0,role TEXT DEFAULT 'user',blocked INTEGER DEFAULT 0,failures INTEGER DEFAULT 0,locked REAL DEFAULT 0,secret TEXT,pending_secret TEXT,last_step INTEGER DEFAULT -1,epoch INTEGER DEFAULT 0,oidc_sub TEXT UNIQUE);
        CREATE TABLE IF NOT EXISTS tokens(hash TEXT PRIMARY KEY,uid INTEGER,kind TEXT,expires REAL,used INTEGER DEFAULT 0);
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,at TEXT,ip TEXT,email TEXT,result TEXT);
        CREATE TABLE IF NOT EXISTS rates(key TEXT PRIMARY KEY,n INTEGER,until REAL);
        CREATE TABLE IF NOT EXISTS outbox(id INTEGER PRIMARY KEY,email TEXT,subject TEXT,body TEXT);
        '''); db().commit()
    def execute(sql,args=()):
        cur=db().execute(sql,args); db().commit(); return cur
    def user(): return db().execute('SELECT * FROM users WHERE id=?',(session.get('uid'),)).fetchone()
    def log(email,result):
        execute("INSERT INTO audit(at,ip,email,result) VALUES(datetime('now'),?,?,?)",(request.remote_addr,email[:254],result))
    def limited(key,limit,seconds):
        now=time.time(); row=db().execute('SELECT * FROM rates WHERE key=?',(key,)).fetchone()
        n=1 if not row or row['until']<now else row['n']+1
        until=now+seconds if not row or row['until']<now else row['until']
        execute('INSERT OR REPLACE INTO rates VALUES(?,?,?)',(key,n,until))
        if n>limit: abort(429)
    @app.before_request
    def guards():
        session.setdefault('csrf',secrets.token_urlsafe(24))
        if request.method=='POST' and not secrets.compare_digest(session['csrf'],request.form.get('csrf','')): abort(400)
        if session.get('uid'):
            u=user()
            if not u or u['blocked'] or not u['active'] or u['epoch']!=session.get('epoch'):
                session.clear(); return redirect('/login')
    @app.after_request
    def headers(r):
        r.headers.update({'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
            'Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; form-action 'self'"})
        return r
    def required(admin=False):
        def dec(fn):
            @wraps(fn)
            def wrapped(*a,**kw):
                u=user()
                if not u: return redirect('/login')
                if admin and u['role']!='admin': abort(403)
                return fn(*a,**kw)
            return wrapped
        return dec
    def page(view,**kw): return render_template('index.html',view=view,u=user(),**kw)
    def policy(p):
        return len(p)>=8 and len(p)<=128 and any(c.isupper() for c in p) and any(c.islower() for c in p) and any(c.isdigit() for c in p) and any(not c.isalnum() and not c.isspace() for c in p)
    def email():
        e=request.form.get('email','').strip().lower()
        if len(e)>254 or '@' not in e or '.' not in e.split('@')[-1]: abort(400)
        return e
    def mail(e,subject,body):
        if app.config['DEMO']: execute('INSERT INTO outbox(email,subject,body) VALUES(?,?,?)',(e,subject,body))
        else:
            msg=EmailMessage();msg['To']=e;msg['From']=os.environ['SMTP_FROM'];msg['Subject']=subject;msg.set_content(body)
            with smtplib.SMTP_SSL(os.environ['SMTP_HOST'],465) as s:
                s.login(os.environ['SMTP_USER'],os.environ['SMTP_PASSWORD']);s.send_message(msg)
    def token(u,kind):
        raw=secrets.token_urlsafe(32)
        execute('UPDATE tokens SET used=1 WHERE uid=? AND kind=?',(u['id'],kind))
        execute('INSERT INTO tokens VALUES(?,?,?,?,0)',(hashlib.sha256(raw.encode()).hexdigest(),u['id'],kind,time.time()+900))
        mail(u['email'],'Активація' if kind=='activate' else 'Відновлення пароля',url_for(kind,token=raw,_external=True))
    def valid_token(raw,kind):
        return db().execute('SELECT * FROM tokens WHERE hash=? AND kind=? AND used=0 AND expires>?',(hashlib.sha256(raw.encode()).hexdigest(),kind,time.time())).fetchone()
    def establish(u):
        session.clear();session.update(uid=u['id'],epoch=u['epoch'],csrf=secrets.token_urlsafe(24));session.permanent=True
    @app.route('/')
    def index(): return redirect('/profile' if user() else '/login')
    @app.route('/captcha')
    def captcha():
        text=''.join(secrets.choice('ABCDEFGHJKLMNPQRSTUVWXYZ23456789') for _ in range(5))
        session['captcha_hash']=hashlib.sha256(text.encode()).hexdigest();session['captcha_exp']=time.time()+120
        im=Image.new('RGB',(240,75),'#edf5fa');d=ImageDraw.Draw(im)
        try: font=ImageFont.truetype('C:/Windows/Fonts/consolab.ttf',34)
        except OSError: font=ImageFont.load_default(size=32)
        for i,c in enumerate(text): d.text((18+i*43,12+secrets.randbelow(10)),c,font=font,fill='#123a57')
        for _ in range(8): d.line(tuple(secrets.randbelow(75) if i%2 else secrets.randbelow(240) for i in range(4)),fill='#8db7c6',width=1)
        b=io.BytesIO();im.save(b,format='PNG');b.seek(0);return send_file(b,mimetype='image/png')
    @app.route('/register',methods=['GET','POST'])
    def register():
        if request.method=='GET': return page('register')
        limited('register:'+request.remote_addr,20,600)
        e=email();p=request.form.get('password','')
        cap=session.pop('captcha_hash',''); exp=session.pop('captcha_exp',0)
        if not policy(p): return page('register',error='Пароль: мінімум 8 символів, великі та малі літери, цифра і спеціальний символ.'),400
        if exp<time.time() or not secrets.compare_digest(cap,hashlib.sha256(request.form.get('captcha','').upper().encode()).hexdigest()): return page('register',error='CAPTCHA неправильна або прострочена. Оновіть зображення.'),400
        try:
            cur=execute('INSERT INTO users(email,password) VALUES(?,?)',(e,generate_password_hash(p,method='scrypt:32768:8:1')))
            token(db().execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone(),'activate')
        except sqlite3.IntegrityError: pass
        return page('message',message='Якщо адреса доступна для реєстрації, надіслано посилання активації. Термін дії 15 хвилин.')
    @app.route('/activate/<token>',methods=['GET','POST'])
    def activate(token):
        t=valid_token(token,'activate')
        if not t: return page('message',message='Посилання недійсне або прострочене.'),400
        if request.method=='GET': return page('confirm',message='Підтвердьте активацію облікового запису.')
        with db():
            cur=db().execute('UPDATE tokens SET used=1 WHERE hash=? AND used=0 AND expires>?',(t['hash'],time.time()))
            if cur.rowcount!=1: abort(400)
            db().execute('UPDATE users SET active=1 WHERE id=?',(t['uid'],))
        return page('message',message='Обліковий запис активовано. Можна увійти.')
    @app.route('/login',methods=['GET','POST'])
    def login():
        if request.method=='GET': return page('login')
        limited('login:'+request.remote_addr,60,600)
        e=email();u=db().execute('SELECT * FROM users WHERE email=?',(e,)).fetchone()
        if u and (u['blocked'] or u['locked']>time.time()):
            log(e,'BLOCKED');return page('login',error='Вхід тимчасово недоступний. Спробуйте пізніше.'),429
        if not u or not u['password'] or not check_password_hash(u['password'],request.form.get('password','')):
            if u:
                n=u['failures']+1;execute('UPDATE users SET failures=?,locked=? WHERE id=?',(n,time.time()+300 if n>=5 else 0,u['id']))
            log(e,'INVALID_PASSWORD');return page('login',error='Невірні облікові дані.'),401
        if not u['active']: log(e,'INACTIVE');return page('login',error='Активуйте обліковий запис.'),403
        if u['secret']:
            session.clear();session.update(pending=u['id'],pending_exp=time.time()+300,csrf=secrets.token_urlsafe(24));return redirect('/two-factor')
        execute('UPDATE users SET failures=0,locked=0 WHERE id=?',(u['id'],));establish(u);log(e,'LOGIN_OK');return redirect('/profile')
    @app.route('/two-factor',methods=['GET','POST'])
    def two_factor():
        u=db().execute('SELECT * FROM users WHERE id=?',(session.get('pending'),)).fetchone()
        if not u or session.get('pending_exp',0)<time.time() or u['blocked'] or u['locked']>time.time(): abort(403)
        if request.method=='GET': return page('otp')
        limited('otp:'+str(u['id']),5,300)
        totp=pyotp.TOTP(cipher.decrypt(u['secret'].encode()).decode());step=int(time.time()//30)
        if step<=u['last_step'] or not totp.verify(request.form.get('code',''),valid_window=0):
            log(u['email'],'INVALID_OTP');return page('otp',error='Невірний або повторно використаний код.'),401
        execute('UPDATE users SET last_step=?,failures=0,locked=0 WHERE id=?',(step,u['id']));establish(u);log(u['email'],'LOGIN_2FA_OK');return redirect('/profile')
    @app.route('/profile')
    @required()
    def profile(): return page('profile')
    @app.route('/2fa/setup',methods=['POST'])
    @required()
    def setup():
        u=user()
        if not u['password'] or not check_password_hash(u['password'],request.form.get('password','')): abort(403)
        if u['secret']: abort(400)
        secret=pyotp.random_base32();execute('UPDATE users SET pending_secret=? WHERE id=?',(cipher.encrypt(secret.encode()).decode(),u['id']))
        return page('setup',secret=secret,uri=pyotp.TOTP(secret).provisioning_uri(u['email'],issuer_name='SecureAccounts Lab6'))
    @app.route('/2fa/confirm',methods=['POST'])
    @required()
    def confirm_2fa():
        u=user();limited('setup:'+str(u['id']),5,300)
        if not u['pending_secret']: abort(400)
        sec=cipher.decrypt(u['pending_secret'].encode()).decode()
        if not pyotp.TOTP(sec).verify(request.form.get('code','')): abort(400)
        execute('UPDATE users SET secret=pending_secret,pending_secret=NULL,last_step=-1,epoch=epoch+1 WHERE id=?',(u['id'],));session['epoch']=u['epoch']+1
        log(u['email'],'2FA_ENABLED');return redirect('/profile')
    @app.route('/2fa/disable',methods=['POST'])
    @required()
    def disable_2fa():
        u=user();limited('disable:'+str(u['id']),5,300)
        if not u['secret'] or not check_password_hash(u['password'] or '',request.form.get('password','')): abort(403)
        if not pyotp.TOTP(cipher.decrypt(u['secret'].encode()).decode()).verify(request.form.get('code','')): abort(403)
        execute('UPDATE users SET secret=NULL,epoch=epoch+1 WHERE id=?',(u['id'],));session['epoch']=u['epoch']+1;log(u['email'],'2FA_DISABLED');return redirect('/profile')
    @app.route('/forgot',methods=['GET','POST'])
    def forgot():
        if request.method=='GET': return page('forgot')
        limited('reset:'+request.remote_addr,5,600);e=email();u=db().execute('SELECT * FROM users WHERE email=?',(e,)).fetchone()
        if u and u['password']: token(u,'reset')
        return page('message',message='Якщо обліковий запис існує, надіслано лист відновлення. Посилання діє 15 хвилин.')
    @app.route('/reset/<token>',methods=['GET','POST'])
    def reset(token):
        t=valid_token(token,'reset')
        if not t: return page('message',message='Посилання недійсне або прострочене.'),400
        if request.method=='GET': return page('reset')
        p=request.form.get('password','')
        if not policy(p): return page('reset',error='Пароль не відповідає політиці.'),400
        hashed=generate_password_hash(p,method='scrypt:32768:8:1')
        with db():
            cur=db().execute('UPDATE tokens SET used=1 WHERE hash=? AND used=0 AND expires>?',(t['hash'],time.time()))
            if cur.rowcount!=1: abort(400)
            db().execute('UPDATE users SET password=?,epoch=epoch+1,failures=0,locked=0 WHERE id=?',(hashed,t['uid']))
        session.clear();return page('message',message='Пароль змінено. Попередні сесії відкликано. 2FA залишається увімкненою.')
    @app.route('/logout',methods=['POST'])
    def logout(): session.clear();return redirect('/login')
    @app.route('/admin')
    @required(admin=True)
    def admin(): return page('admin',users=db().execute('SELECT * FROM users').fetchall(),logs=db().execute('SELECT * FROM audit ORDER BY id DESC LIMIT 100').fetchall())
    @app.route('/admin/<int:uid>/<action>',methods=['POST'])
    @required(admin=True)
    def manage(uid,action):
        if uid==user()['id'] or action not in ('block','unblock'): abort(400)
        execute('UPDATE users SET blocked=?,failures=0,locked=0,epoch=epoch+1 WHERE id=?',(action=='block',uid));log(user()['email'],f'ADMIN_{action.upper()}:{uid}');return redirect('/admin')
    @app.route('/mail')
    def outbox():
        if not app.config['DEMO'] or request.remote_addr not in ('127.0.0.1','::1'): abort(404)
        return page('mail',letters=db().execute('SELECT * FROM outbox ORDER BY id DESC LIMIT 20').fetchall())
    @app.route('/oidc/login')
    def oidc_login(): return oauth.idp.authorize_redirect(url_for('oidc_callback',_external=True))
    @app.route('/oidc/callback')
    def oidc_callback():
        try: tok=oauth.idp.authorize_access_token();info=tok['userinfo']
        except Exception: return page('message',message='OIDC відповідь відхилена.'),400
        sub=info['iss']+'|'+info['sub']
        u=db().execute('SELECT * FROM users WHERE oidc_sub=?',(sub,)).fetchone()
        if not u:
            # No automatic email linking: a verified email alone does not link a local identity.
            if info.get('email_verified') is not True: abort(403)
            try: execute('INSERT INTO users(email,active,oidc_sub) VALUES(?,1,?)',(info['email'],sub))
            except sqlite3.IntegrityError: return page('message',message='Адреса вже зайнята. Автоматичне зв’язування облікових записів заборонено.'),409
            u=db().execute('SELECT * FROM users WHERE oidc_sub=?',(sub,)).fetchone()
        if u['blocked'] or u['locked']>time.time() or not u['active']: abort(403)
        if u['secret']:
            session.clear();session.update(pending=u['id'],pending_exp=time.time()+300,csrf=secrets.token_urlsafe(24));return redirect('/two-factor')
        establish(u);log(u['email'],'OIDC_OK');return redirect('/profile')
    @app.cli.command('create-admin')
    def create_admin():
        import getpass
        e=input('Admin email: ').strip().lower();p=getpass.getpass('Admin password: ')
        if not policy(p): raise ValueError('Password policy failed')
        execute("INSERT INTO users(email,password,active,role) VALUES(?,?,1,'admin')",(e,generate_password_hash(p,method='scrypt:32768:8:1')))
    return app

if __name__=='__main__': create_app().run(host='127.0.0.1',port=5000,debug=False)
