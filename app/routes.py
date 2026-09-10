"""OAuth Misconfiguration Lab — 4 skenario BBP.

Skenario (default RENTAN, bisa di-fix per skenario):
  s1 missing state            -> OAuth login CSRF / cross-account link
  s2 redirect_uri cacat       -> authorization code + token bocor ke "server penyerang"
  s3 account linking by email tanpa email_verified -> pre-account takeover
  s4 no PKCE + code reusable  -> authorization code replay -> ATO
"""
import hashlib
import secrets
import base64
import urllib.parse as up

from flask import Blueprint, Flask, jsonify, redirect, render_template, request, session, url_for

from . import models as M

bp = Blueprint('main', __name__)

PORT = 5070
BASE = f'http://127.0.0.1:{PORT}'
CLIENT_ID = 'oauthlab-client'
CB = f'{BASE}/cb'                       # callback "resmi" client app
EVIL_URI = f'{BASE}/evil/s2_capture'    # "server penyerang" di path /evil (simulasi)
SCOPE = 'profile email'


# ============ HELPERS ============
def scenario(k):
    return M.setting(k) == 1  # True = rentan


def sha256_b64url(s):
    return base64.urlsafe_b64encode(hashlib.sha256(s.encode()).digest()).decode().rstrip('=')


def issueno_id():
    return secrets.token_urlsafe(24)


def authorize_flow(username, redirect_uri=CB, state='', challenge=''):
    """Simulasi penyelesaian /oauth/authorize oleh browser user tertentu.
    Menghasilkan auth code (tanpa menunggu halaman approve)."""
    code = issueno_id()
    M.store_code(code, username, redirect_uri, state, challenge)
    return code


def redeem_code(code, verifier=None):
    """Endpoint token exchange. Logika PKCE + single-use mengikuti mode s4."""
    row = M.get_code(code)
    if not row:
        return None, 'authorization code tidak ditemukan'
    if not scenario('s4'):  # mode FIX: PKCE + single-use
        if not row['challenge']:
            return None, 'PKCE diwajibkan client (challenge kosong)'
        if not verifier or sha256_b64url(verifier) != row['challenge']:
            return None, 'code_verifier tidak cocok → PKCE gagal'
        if row['used']:
            return None, 'authorization code sudah terpakai → replay diblokir'
        M.mark_used(code)
    else:  # mode RENTAN: tanpa PKCE & code bisa dipakai berulang
        M.log('s4', 'TOKEN EXCHANGE tanpa PKCE | code=' + code[:10] + '…')
    token = secrets.token_urlsafe(32)
    M.store_token(token, row['username'])
    return token, None


def claim_from_token(token):
    t = M.get_token(token)
    if not t:
        return None
    u = M.get_user(t['username'])
    if not u:
        return None
    return {'sub': u['username'], 'email': u['email'], 'email_verified': u['email_verified']}


def client_login(code, state, verifier=None):
    """Login callback client:
    - s1 FIX  : state wajib cocok dengan yang client kirim.
    - token exchange (PKCE via s4).
    - s3 FIX  : email_verified wajib true sebelum linking akun client."""
    if not scenario('s1'):  # mode FIX: state wajib
        if not state or not session.get('oauth_state') or state != session.get('oauth_state'):
            return None, 'state parameter missing/mismatch → ditolak (anti login CSRF)'
    token, err = redeem_code(code, verifier or session.get('oauth_verifier'))
    if err:
        return None, err
    t = M.get_token(token)
    claims = claim_from_token(token)
    if not claims:
        return None, 'token/token tidak valid'
    account = M.user_by_email(claims['email'])
    if not account:
        return None, 'tidak ada akun client untuk email ' + claims['email']
    if not scenario('s3') and not claims['email_verified']:
        return None, 'email NOT_VERIFIED → account linking ditolak'
    session['client_user'] = account['username']
    return account, token


def validate_redirect_uri(uri):
    """Mode s2 RENTAN: hanya host yang dicek → path apa pun lolos (termasuk /evil/*).
    Mode s2 FIX: harus sama persis dengan callback resmi client."""
    if scenario('s2'):
        p = up.urlparse(uri)
        return p.scheme in ('http', 'https') and p.hostname in ('127.0.0.1', 'localhost')
    return uri == CB


def build_auth_url(evil=False):
    """Buat URL /oauth/authorize ala client app.
    state & PKCE hanya ditambahkan saat mode masing-masing (s1, s4) sudah di-fix."""
    q = {'client_id': CLIENT_ID, 'scope': SCOPE, 'response_type': 'code'}
    if scenario('s1'):
        session['oauth_state'] = secrets.token_urlsafe(16)
        q['state'] = session['oauth_state']
    if scenario('s4'):
        session['oauth_verifier'] = secrets.token_urlsafe(32)
        q['code_challenge'] = sha256_b64url(session['oauth_verifier'])
        q['code_challenge_method'] = 'S256'
    q['redirect_uri'] = EVIL_URI if evil else CB
    return BASE + '/oauth/authorize?' + up.urlencode(q)


# ============ HALAMAN ============
@bp.route('/')
def index():
    return render_template('index.html', modes=M.all_settings(),
                           provider=session.get('provider_user'),
                           client_user=session.get('client_user'))


@bp.route('/logs')
def logs():
    return render_template('logs.html', logs=M.last_logs())


@bp.route('/api/state')
def api_state():
    return jsonify({
        'modes': M.all_settings(),
        'provider': session.get('provider_user'),
        'client_user': session.get('client_user'),
    })


# ---------- IDENTITAS PROVIDER (simulasi akun di OAuth provider) ----------
@bp.route('/provider')
def provider():
    return render_template('provider.html', current=session.get('provider_user'))


@bp.route('/oauth/login', methods=['POST'])
def oauth_login():
    ident = request.form.get('identity')
    if ident in ('attacker', 'victim', 'evilclone'):
        session['provider_user'] = ident
        M.log('meta', f'Provider login sebagai: {ident}')
    return redirect(request.referrer or '/')


# ---------- OAUTH PROVIDER ----------
@bp.route('/oauth/authorize')
def oauth_authorize():
    uri = request.args.get('redirect_uri', '')
    if not validate_redirect_uri(uri):
        M.log('s2', f'redirect_uri DITOLAK oleh authorize: {uri}')
        return render_template('approve.html', error='redirect_uri tidak sah (mode fix s2)'), 400
    if not session.get('provider_user'):
        next_url = up.urlencode({'next': request.url})
        return redirect('/provider?next=' + next_url)
    return render_template('approve.html', error=None,
                           uri=uri,
                           code_challenge=request.args.get('code_challenge', ''),
                           state=request.args.get('state', ''))


@bp.route('/oauth/approve', methods=['POST'])
def oauth_approve():
    uri = request.form['redirect_uri']
    if not validate_redirect_uri(uri):
        return render_template('approve.html', error='redirect_uri tidak sah'), 400
    user = session.get('provider_user')
    if not user:
        return redirect('/provider')
    code = issueno_id()
    M.store_code(code, user, uri, request.form.get('state', ''), request.form.get('challenge', ''))
    sep = '&' if '?' in uri else '?'
    return redirect(f"{uri}{sep}code={code}&state={up.quote(request.form.get('state', ''))}")


@bp.route('/oauth/token', methods=['POST'])
def oauth_token():
    code = request.form.get('code', '')
    verifier = request.form.get('code_verifier', '')
    token, err = redeem_code(code, verifier or None)
    if err:
        return jsonify({'error': err}), 400
    return jsonify({'access_token': token, 'token_type': 'Bearer', 'scope': SCOPE})


@bp.route('/oauth/me')
def oauth_me():
    auth = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '')
    claims = claim_from_token(token)
    if not claims:
        return jsonify({'error': 'invalid token'}), 401
    return jsonify(claims)


# ============ CLIENT CALLBACK (login normal) ============
@bp.route('/cb')
def cb():
    code = request.args.get('code', '')
    state = request.args.get('state', '')
    account, err = client_login(code, state)
    if err:
        return redirect('/?err=' + up.quote(err))
    M.log('meta', f'Client login sukses sebagai: {account["username"]}')
    return redirect('/?logged=' + account['username'])


# ============ S2: FLOW KE "SERVER PENYERANG" ============
@bp.route('/s2/login')
def s2_login():
    return redirect(build_auth_url(evil=True))


@bp.route('/evil/s2_capture')
def evil_capture():
    code = request.args.get('code', '')
    M.log('s2', f'[EVIL SERVER] menangkap authorization code: {code}')
    token, err = redeem_code(code, None)  # penyerang TIDAK punya verifier
    if err:
        return render_template('evil_capture.html', code=code, token=None, err=err)
    M.log('s2', f'[EVIL SERVER] menukar code → access_token (victim): {token[:12]}…')
    claims = claim_from_token(token)
    victim = M.user_by_email(claims['email']) if claims else None
    M.log('s2', f'[EVIL SERVER] claims {claims}')
    return render_template('evil_capture.html', code=code, token=token, claims=claims, victim=victim)


# ============ MITM: CYBERNESS / POC WALKTHROUGH ============
@bp.post('/api/poc/<s>')
def poc(s):
    if s == 's1':
        return poc_s1()
    if s == 's2':
        return poc_s2()
    if s == 's3':
        return poc_s3()
    if s == 's4':
        return poc_s4()
    return jsonify({'ok': False, 'msg': 'unknown'}), 404


def _finish(ok, steps, flag=None):
    return jsonify({'ok': ok, 'mode': 'FIXED' if not ok else 'RENTAN', 'steps': steps, 'flag': flag})


def _new_oauth_session():
    """Simulasi client yang "benar": selalu menyiapkan state + PKCE (S256).
    Kontrol yang diuji hanya menentukan mana yang benar-benar hilang."""
    state = secrets.token_urlsafe(16)
    ver = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['oauth_verifier'] = ver
    return state, sha256_b64url(ver)


def poc_s1():
    """Missing state → login CSRF: attacker pre-auth code, korban membuka link-nya."""
    steps = []
    if scenario('s1'):
        # client RENTAN: tidak menyertakan state pada authorize & tidak memverifikasi di callback
        code_a = authorize_flow('attacker', CB, state='', challenge='')
        steps.append('Attacker memakai authorize URL client (TANPA state) → code diterbitkan: ' + code_a[:10] + '…')
        steps.append('Korban membuka link itu → callback /cb menerima code tanpa state (client tidak memverifikasi).')
        user, err = client_login(code_a, state='')
        if user:
            steps.append(f'RESULT: sesi client korban jadi {user["username"]} ({user["email"]}) — OAuth login CSRF berhasil.')
            return _finish(True, steps)
        return _finish(False, steps + [err])
    # mode FIX: client menyertakan state, attacker lupa / mengirim state kosong
    state, chal = _new_oauth_session()
    code_a = authorize_flow('attacker', CB, state=state, challenge=chal)
    steps.append('Client FIXED mewajibkan state: attacker membangun link tanpa state → callback dengan state kosong.')
    user, err = client_login(code_a, state='', verifier=session['oauth_verifier'])
    steps.append(f'callback ditolak ({err}) — login korban tidak jadi attacker.')
    return _finish(False, steps)


def poc_s2():
    """redirect_uri host-only → code + token bocor ke server penyerang (/evil/*)."""
    steps = []
    ok = validate_redirect_uri(EVIL_URI)
    if ok:
        steps.append(f'validate_redirect_uri("{EVIL_URI}") → LOLOS (host doang dicek, path bebas).')
        state, chal = _new_oauth_session()
        code = authorize_flow('victim', EVIL_URI, state=state, challenge=chal)
        steps.append('Korban klik login → code dikirim ke /evil/s2_capture (bukan ke callback resmi): ' + code[:10] + '…')
        token, err = redeem_code(code, session['oauth_verifier'])
        if not token:
            return _finish(True, steps + ['Token exchange: ' + err])
        claims = claim_from_token(token)
        victim = M.user_by_email(claims['email']) if claims else None
        steps.append(f'[EVIL SERVER] menukar code → access_token victim: {token[:14]}…')
        steps.append(f'[EVIL SERVER] GET /oauth/me → claims {claims}')
        steps.append(f'ATTACKER MEMEGANG AKSES PENUH VICTIM → flag: {victim["flag"]}' if victim and victim['flag'] else 'flag target tidak ketemu.')
        return _finish(True, steps, victim['flag'] if victim else None)
    steps.append('redirect_uri ditolak saat authorize (mode fix): hanya callback resmi yang boleh.')
    return _finish(False, steps)


def poc_s3():
    """Account linking by email tanpa email_verified → ATO (pre-account takeover)."""
    steps = []
    identity = 'evilclone'  # akun attacker ber-email victim@corp.test, UNVERIFIED
    steps.append(f'Attacker daftar akun di provider pakai email victim@corp.test ({identity}), email_verified=0.')
    state, chal = _new_oauth_session()
    code = authorize_flow(identity, CB, state=state, challenge=chal)
    steps.append('Attacker login OAuth ke client (state+PKCE valid) → token berisi email victim, unverified.')
    user, err = client_login(code, state=state, verifier=session['oauth_verifier'])
    if user:
        if user['username'] == 'victim':
            steps.append(f'RESULT: client menautkan akun hanya dari email → sesi = {user["username"]} (VICTIM). email_verified TIDAK dicek!')
            steps.append(f'DATA VICTIM TERBACA → flag: {user["flag"]}')
            return _finish(True, steps, user['flag'])
        steps.append(f'RESULT: sesi = {user["username"]} (bukan target)')
        return _finish(True, steps)
    steps.append(f'BLOCKED: {err}')
    return _finish(False, steps)


def poc_s4():
    """No PKCE + code reuse → code replay ATO."""
    steps = []
    if scenario('s4'):
        # client RENTAN: tanpa code_challenge, token endpoint tidak cek verifier & code satu-time
        code = authorize_flow('victim', CB, state='', challenge='')
        steps.append('Client RENTAN: authorize tanpa PKCE, token endpoint tidak cek verifier/reuse.')
        steps.append('Attacker mengintersepsi code korban: ' + code[:10] + '…')
        tk1, e1 = redeem_code(code, None)
        tk2, e2 = redeem_code(code, None)  # REPLAY, code di-pakai lagi
        steps.append('exchange #1 → ' + (tk1[:14] + '…' if tk1 else e1))
        steps.append('exchange #2 (replay) → ' + (tk2[:14] + '… — token LAGI terbit, code bisa dipakai ulang!' if tk2 else e2))
        token = tk2 or tk1
        claims = claim_from_token(token or '')
        if claims:
            victim = M.user_by_email(claims['email'])
            steps.append(f'Attacker pakai token → /oauth/me → {claims}')
            steps.append(f'DATA VICTIM TERBACA → flag: {victim["flag"]}' if victim and victim['flag'] else 'flag target tidak ketemu.')
            return _finish(True, steps, victim['flag'] if victim else None)
        return _finish(True, steps + ['claims gagal'])
    # mode FIX: PKCE S256 + single-use code
    state, chal = _new_oauth_session()
    code = authorize_flow('victim', CB, state=state, challenge=chal)
    steps.append('Client FIXED: PKCE S256 + authorization code one-time-use.')
    steps.append('Attacker (yang sempat menangkap code) mencoba exchange dengan verifier:')
    tk1, e1 = redeem_code(code, session['oauth_verifier'])
    tk2, e2 = redeem_code(code, session['oauth_verifier'])  # replay
    steps.append('exchange #1 → ' + (tk1[:12] + '…' if tk1 else e1))
    if tk1 and not tk2:
        steps.append(f'exchange #2 (replay) ditolak → "{e2}" → replay gagal.')
    elif not tk1:
        steps.append('exchange #1 pun gagal: ' + e1)
    return _finish(False, steps)


# ============ TOGGLE MODE ============
@bp.post('/api/toggle/<s>')
def toggle(s):
    if s not in ('s1', 's2', 's3', 's4'):
        return jsonify({'ok': False}), 400
    cur = M.setting(s)
    M.set_setting(s, 0 if cur else 1)
    M.log('meta', f'Scenario {s.upper()} → {"RENTAN (vulnerable)" if M.setting(s) else "FIXED (secure)"}')
    # saat klien di-logout, jangan ubah sesi client_user (simulasi sesi nyata)
    return jsonify({'ok': True, 'scenario': s, 'vulnerable': bool(M.setting(s))})


@bp.post('/api/logout_client')
def logout_client():
    session.pop('client_user', None)
    return jsonify({'ok': True})