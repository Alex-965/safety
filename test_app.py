import hashlib, re, time
import pytest, pyotp
from werkzeug.security import generate_password_hash
from app import create_app
from cryptography.fernet import Fernet

@pytest.fixture
def env(tmp_path):
    app=create_app({'TESTING':True,'DATABASE':str(tmp_path/'test.db'),'SECRET_KEY':'test-key','FERNET_KEY':Fernet.generate_key()})
    client=app.test_client()
    with app.app_context():
        from flask import g
        # initialize a user via public registration in helper
    return app,client

def post(c,path,data=None):
    c.get('/login')
    with c.session_transaction() as s: csrf=s['csrf']
    return c.post(path,data={'csrf':csrf,**(data or {})})

def register(c,e='student@example.test',p='Student!2026'):
    c.get('/register')
    with c.session_transaction() as s:
        s['captcha_hash']=hashlib.sha256(b'ABCDE').hexdigest();s['captcha_exp']=time.time()+120
    return post(c,'/register',{'email':e,'password':p,'captcha':'ABCDE'})

def sql(app,q,args=()):
    import sqlite3
    con=sqlite3.connect(app.config['DATABASE']);con.row_factory=sqlite3.Row
    cur=con.execute(q,args);rows=cur.fetchall();con.commit();con.close();return rows

def active(app,c):
    register(c);link=sql(app,'SELECT body FROM outbox')[-1]['body'];path=link.replace('http://localhost','')
    assert post(c,path).status_code==200
    return path

def login(c,password='Student!2026'):
    return post(c,'/login',{'email':'student@example.test','password':password})

def test_password_policy(env):
    app,c=env
    for p in ['123','alllower1!','ALLUPPER1!','NoDigits!!!','NoSpecial123']:
        assert register(c,p=p).status_code==400
    assert not sql(app,'SELECT * FROM users')

def test_captcha_expiry_replay_and_wrong(env):
    app,c=env;c.get('/register')
    assert post(c,'/register',{'email':'a@example.test','password':'Student!2026','captcha':'wrong'}).status_code==400
    with c.session_transaction() as s: s['captcha_hash']=hashlib.sha256(b'ABCDE').hexdigest();s['captcha_exp']=time.time()-1
    assert post(c,'/register',{'email':'a@example.test','password':'Student!2026','captcha':'ABCDE'}).status_code==400
    assert register(c).status_code==200
    assert post(c,'/register',{'email':'b@example.test','password':'Student!2026','captcha':'ABCDE'}).status_code==400

def test_hash_activation_and_token_reuse(env):
    app,c=env;register(c)
    u=sql(app,'SELECT * FROM users')[0];assert u['password'].startswith('scrypt:');assert 'Student!2026' not in u['password']
    assert login(c).status_code==403
    path=sql(app,'SELECT body FROM outbox')[0]['body'].replace('http://localhost','')
    assert c.get(path).status_code==200
    assert sql(app,'SELECT active FROM users')[0]['active']==0
    assert post(c,path).status_code==200
    assert post(c,path).status_code==400
    assert login(c).status_code==302

def test_lock_audit_and_admin(env):
    app,c=env;active(app,c)
    for _ in range(5): assert login(c,'wrong').status_code==401
    assert login(c).status_code==429
    logs=sql(app,'SELECT * FROM audit');assert logs[-1]['result']=='BLOCKED';assert logs[0]['ip']=='127.0.0.1'
    sql(app,'INSERT INTO users(email,password,active,role) VALUES(?,?,1,?)',('admin@example.test',generate_password_hash('Admin!2026'),'admin'))
    post(c,'/login',{'email':'admin@example.test','password':'Admin!2026'})
    assert c.get('/admin').status_code==200
    uid=sql(app,'SELECT id FROM users WHERE email=?',('student@example.test',))[0]['id']
    assert post(c,f'/admin/{uid}/block').status_code==302
    assert sql(app,'SELECT blocked FROM users WHERE id=?',(uid,))[0]['blocked']==1
    assert post(c,f'/admin/{uid}/unblock').status_code==302
    post(c,'/logout');assert login(c).status_code==302

def test_rbac_csrf_and_mass_assignment(env):
    app,c=env;active(app,c);login(c)
    assert c.get('/admin').status_code==403
    assert c.post('/logout').status_code==400
    assert post(c,'/admin/1/block').status_code==403
    assert c.get('/profile?uid=2').status_code==200
    assert sql(app,'SELECT role FROM users')[0]['role']=='user'

def test_totp_enable_login_replay_disable(env):
    app,c=env;active(app,c);login(c)
    r=post(c,'/2fa/setup',{'password':'Student!2026'});assert r.status_code==200
    secret=re.search(rb'<code>([A-Z2-7]+)</code>',r.data)[1].decode()
    assert post(c,'/2fa/confirm',{'code':'bad'}).status_code==400
    assert post(c,'/2fa/confirm',{'code':pyotp.TOTP(secret).now()}).status_code==302
    assert secret not in sql(app,'SELECT secret FROM users')[0]['secret']
    post(c,'/logout');assert login(c).location.endswith('/two-factor')
    assert c.get('/profile').status_code==302
    assert post(c,'/two-factor',{'code':'000000' if pyotp.TOTP(secret).now()!='000000' else '111111'}).status_code==401
    assert post(c,'/two-factor',{'code':pyotp.TOTP(secret).now()}).status_code==302
    post(c,'/logout');login(c)
    assert post(c,'/two-factor',{'code':pyotp.TOTP(secret).now()}).status_code==401
    sql(app,'UPDATE users SET last_step=-1');assert post(c,'/two-factor',{'code':pyotp.TOTP(secret).now()}).status_code==302
    assert post(c,'/2fa/disable',{'password':'wrong','code':pyotp.TOTP(secret).now()}).status_code==403
    assert post(c,'/2fa/disable',{'password':'Student!2026','code':pyotp.TOTP(secret).now()}).status_code==302

def test_reset_expiry_reuse_and_session_revocation(env):
    app,c=env;active(app,c);login(c)
    other=app.test_client();login(other)
    assert post(c,'/forgot',{'email':'student@example.test'}).status_code==200
    path=sql(app,'SELECT body FROM outbox ORDER BY id DESC')[0]['body'].replace('http://localhost','')
    assert post(c,path,{'password':'short'}).status_code==400
    assert post(c,path,{'password':'Changed!2026'}).status_code==200
    assert post(c,path,{'password':'Changed!2026'}).status_code==400
    assert other.get('/profile').status_code==302
    assert login(c).status_code==401
    assert login(c,'Changed!2026').status_code==302
    post(c,'/forgot',{'email':'student@example.test'});sql(app,'UPDATE tokens SET expires=0')
    path=sql(app,'SELECT body FROM outbox ORDER BY id DESC')[0]['body'].replace('http://localhost','')
    assert c.get(path).status_code==400

def test_reset_enumeration_and_mail_mode(env):
    app,c=env;active(app,c)
    a=post(c,'/forgot',{'email':'student@example.test'});b=post(c,'/forgot',{'email':'nobody@example.test'})
    assert a.data==b.data
    app.config['DEMO']=False;assert c.get('/mail').status_code==404

def test_rate_limit(env):
    app,c=env
    for _ in range(5): assert post(c,'/forgot',{'email':'nobody@example.test'}).status_code==200
    assert post(c,'/forgot',{'email':'nobody@example.test'}).status_code==429

def test_block_revokes_existing_session(env):
    app,c=env;active(app,c);login(c)
    sql(app,'UPDATE users SET blocked=1,epoch=epoch+1')
    assert c.get('/profile').status_code==302

def test_oidc_unsolicited_callback(env):
    app,c=env;assert c.get('/oidc/callback?code=forged&state=forged').status_code==400

def test_security_headers(env):
    app,c=env;r=c.get('/login')
    assert r.headers['Cache-Control']=='no-store';assert r.headers['X-Frame-Options']=='DENY'
    assert c.get('/captcha').mimetype=='image/png'
