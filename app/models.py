import os
import sqlite3
import time

# DB disimpan di luar package: D:\OPENCODE\oauth-lab\database\lab.db
DB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'lab.db')


def connect():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys = ON')
    return c


def init_db():
    c = connect()
    c.executescript('''
    CREATE TABLE IF NOT EXISTS users(
        username      TEXT PRIMARY KEY,
        email         TEXT NOT NULL,
        email_verified INTEGER NOT NULL DEFAULT 1,
        flag          TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS oauth_codes(
        id            INTEGER PRIMARY KEY AUTOINCREMENT,
        code          TEXT NOT NULL,
        username      TEXT NOT NULL,
        redirect_uri  TEXT NOT NULL,
        state         TEXT DEFAULT '',
        challenge     TEXT DEFAULT '',
        used          INTEGER NOT NULL DEFAULT 0,
        created_at    REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_tokens(
        token         TEXT PRIMARY KEY,
        username      TEXT NOT NULL,
        scope         TEXT DEFAULT 'profile email',
        created_at    REAL NOT NULL
    );
    CREATE TABLE IF NOT EXISTS settings(
        k TEXT PRIMARY KEY,
        v INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE IF NOT EXISTS attack_logs(
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        scenario  TEXT NOT NULL,
        detail    TEXT NOT NULL,
        ts        REAL NOT NULL
    );
    ''')
    c.commit()
    c.close()


# ---------- SEED (identitas provider + flag victim) ----------
def seed():
    init_db()
    c = connect()
    if c.execute('SELECT COUNT(*) c FROM users').fetchone()['c'] == 0:
        users = [
            # username, email, email_verified, flag
            ('attacker', 'attacker@evil.com', 1, ''),
            ('victim', 'victim@corp.test', 1, 'OAUTH-LAB{FLAG_Victim_Akun_Ambil_Melalui_OAuth_8841}'),
            ('evilclone', 'victim@corp.test', 0, ''),  # akun attacker pake email victim, BELUM diverifikasi
        ]
        c.executemany('INSERT INTO users(username,email,email_verified,flag) VALUES(?,?,?,?)', users)
    for k in ('s1', 's2', 's3', 's4'):
        if c.execute('SELECT COUNT(*) c FROM settings WHERE k=?', (k,)).fetchone()['c'] == 0:
            c.execute('INSERT INTO settings(k,v) VALUES(?,1)', (k,))  # default: rentan
    c.commit()
    c.close()


# ---------- SETTINGS / MODE ----------
def setting(k):
    c = connect()
    r = c.execute('SELECT v FROM settings WHERE k=?', (k,)).fetchone()
    c.close()
    return r['v'] if r else 1


def set_setting(k, v):
    c = connect()
    c.execute('INSERT OR REPLACE INTO settings(k,v) VALUES(?,?)', (k, 1 if v else 0))
    c.commit()
    c.close()


def all_settings():
    c = connect()
    rows = {r['k']: r['v'] for r in c.execute('SELECT k,v FROM settings')}
    c.close()
    return {k: rows.get(k, 1) for k in ('s1', 's2', 's3', 's4')}


# ---------- USERS ----------
def get_user(username):
    c = connect()
    r = c.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
    c.close()
    return dict(r) if r else None


def user_by_email(email):
    c = connect()
    r = c.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
    c.close()
    return dict(r) if r else None


# ---------- OAUTH CODES / TOKENS ----------
def store_code(code, username, redirect_uri, state, challenge):
    c = connect()
    c.execute('INSERT INTO oauth_codes(code,username,redirect_uri,state,challenge,used,created_at) VALUES(?,?,?,?,?,0,?)',
              (code, username, redirect_uri, state, challenge, time.time()))
    c.commit()
    c.close()


def get_code(code):
    c = connect()
    r = c.execute('SELECT * FROM oauth_codes WHERE code=?', (code,)).fetchone()
    c.close()
    return dict(r) if r else None


def mark_used(code):
    c = connect()
    c.execute('UPDATE oauth_codes SET used=1 WHERE code=?', (code,))
    c.commit()
    c.close()


def store_token(token, username):
    c = connect()
    c.execute('INSERT INTO oauth_tokens(token,username,scope,created_at) VALUES(?,?,?,?)',
              (token, username, 'profile email', time.time()))
    c.commit()
    c.close()


def get_token(token):
    c = connect()
    r = c.execute('SELECT * FROM oauth_tokens WHERE token=?', (token,)).fetchone()
    c.close()
    return dict(r) if r else None


# ---------- ATTACK LOG ----------
def log(scenario, detail):
    c = connect()
    c.execute('INSERT INTO attack_logs(scenario,detail,ts) VALUES(?,?,?)', (scenario, detail, time.time()))
    c.commit()
    c.close()


def last_logs(limit=60):
    c = connect()
    rows = c.execute('SELECT * FROM attack_logs ORDER BY id DESC LIMIT ?', (limit,)).fetchall()
    c.close()
    return [dict(r) for r in rows]