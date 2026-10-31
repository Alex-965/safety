"""Separate LOCAL TEST identity provider. Not a production identity service."""
import secrets,time,hashlib,base64
from flask import Flask,request,jsonify,redirect,session,abort,render_template_string
from urllib.parse import urlencode
from joserfc import jwt
from joserfc.jwk import RSAKey
app=Flask(__name__);app.secret_key=secrets.token_bytes(32)
app.config.update(SESSION_COOKIE_NAME='lab_idp_session',SESSION_COOKIE_HTTPONLY=True,SESSION_COOKIE_SAMESITE='Lax')
key=RSAKey.generate_key(2048,parameters={'kid':'lab-key'})
issuer='http://127.0.0.1:5001';redirect_uri='http://127.0.0.1:5000/oidc/callback'
codes={}
@app.get('/.well-known/openid-configuration')
def discovery():
    return jsonify(issuer=issuer,authorization_endpoint=issuer+'/authorize',token_endpoint=issuer+'/token',jwks_uri=issuer+'/jwks',response_types_supported=['code'],subject_types_supported=['public'],id_token_signing_alg_values_supported=['RS256'],token_endpoint_auth_methods_supported=['client_secret_basic'],code_challenge_methods_supported=['S256'])
@app.get('/jwks')
def jwks(): return jsonify(keys=[key.as_dict(private=False)])
@app.route('/authorize',methods=['GET','POST'])
def authorize():
    if request.method=='GET':
        a=request.args
        if a.get('client_id')!='lab-client' or a.get('redirect_uri')!=redirect_uri or a.get('response_type')!='code' or a.get('code_challenge_method')!='S256' or not a.get('nonce') or not a.get('state') or not a.get('code_challenge') or 'openid' not in a.get('scope','').split(): abort(400)
        session['authorization']=a.to_dict();session['csrf']=secrets.token_urlsafe(24)
        return render_template_string('''<html lang="uk"><meta charset="utf-8"><body style="font:20px Segoe UI;max-width:700px;margin:90px auto;background:#edf3f8"><h1>Local Lab ID</h1><p>Окремий тестовий OIDC-провайдер на порту 5001</p><p>Тестова особа: oidc.student@example.test</p><p>Дозволи: openid email profile</p><p>Цей стенд не перевіряє реальну особу. Для робочої системи підключіть справжнього провайдера.</p><form method="post"><input name="csrf" type="hidden" value="{{csrf}}"><button style="font:inherit;padding:15px">Підтвердити тестовий вхід</button></form></body></html>''',csrf=session['csrf'])
    if not secrets.compare_digest(session.get('csrf',''),request.form.get('csrf','!')): abort(400)
    a=session.pop('authorization',None)
    if not a: abort(400)
    code=secrets.token_urlsafe(32);codes[code]={**a,'expires':time.time()+60}
    return redirect(redirect_uri+'?'+urlencode({'code':code,'state':a['state']}))
@app.post('/token')
def token():
    auth=request.authorization
    if not auth or auth.username!='lab-client' or auth.password!='local-demo-only': abort(401)
    a=codes.pop(request.form.get('code',''),None)
    if not a or a['expires']<time.time() or request.form.get('redirect_uri')!=redirect_uri or request.form.get('grant_type')!='authorization_code': abort(400)
    challenge=base64.urlsafe_b64encode(hashlib.sha256(request.form.get('code_verifier','').encode()).digest()).rstrip(b'=').decode()
    if not secrets.compare_digest(challenge,a['code_challenge']): abort(400)
    now=int(time.time());claims=dict(iss=issuer,sub='student-001',aud='lab-client',iat=now,exp=now+300,nonce=a['nonce'],email='oidc.student@example.test',email_verified=True,name='Тестовий студент')
    return jsonify(access_token=secrets.token_urlsafe(32),token_type='Bearer',expires_in=300,id_token=jwt.encode({'alg':'RS256','kid':'lab-key'},claims,key))
if __name__=='__main__': app.run(host='127.0.0.1',port=5001,debug=False)
