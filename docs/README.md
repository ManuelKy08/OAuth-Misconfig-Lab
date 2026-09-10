# OAuth Misconfiguration Lab

Lab Flask untuk belajar **OAuth 2.0 security misconfigurations** yang paling sering muncul
di program Bug Bounty - mensimulasikan "Sign in with Google/GitHub/Office 365" yang cacat.

- **Provider OAuth** simulasi: `/oauth/authorize`, `/oauth/token`, `/oauth/me`
- **Client app** simulasien (`saldoku`-gaya): callback `/cb`, dashboard
- **Server penyerang** simulasien di path `/evil/*`
- Identitas provider (attacker / victim / evilclone) bisa dipilih di halaman **Provider Identity**
- Mode per skenario: **RENTAN** (default) ↔ **FIXED** (toggle), buktikan sisi defense.

## Menjalankan

```bash
cd D:\OPENCODE\oauth-lab
C:\Program Files\Python313\python.exe -m app.main
# buka http://127.0.0.1:5070
```

Seed otomatis membuat: `attacker@evil.com`, `victim@corp.test` (pemilik flag),
`evilclone` (email victim tapi unverified). Flag: `OAUTH-LAB{FLAG_...}`.

## Skenario & ringkasan finding (BBP)

| # | Vuln | Dampak | Fix |
|---|------|--------|-----|
| s1 | Missing `state` | OAuth login CSRF / akun korban ter-link ke attacker | state random per sesi + validasi di callback |
| s2 | `redirect_uri` hanya cek host | authorization code & access_token bocor ke server attacker | allowlist exact-match redirect_uri |
| s3 | account linking by `email` tanpa `email_verified` | pre-account takeover | jangan percaya email; wajib verified / sub-only mapping |
| s4 | no PKCE + code reusable | code replay → token victim (ATO) | PKCE S256 + one-time code + TTL |

## Cara bermain

1. Login identity provider (mis. `victim`).
2. Klik **Jalankan Exploit** pada kartu scenario yang kamu mau uji.
3. Baca hasil exploit (steps) di kartu, lalu buka **Attacker Logs** untuk jejak lengkap.
4. Toggle skenario ke **FIXED** → jalankan ulang → bandingkan kenapa gagal.
5. Beres...? Export catatan dari Logs, atau screenshoot jadi bukti untuk write-up.

Detail payload & request mentah ada di [`payloads/README.md`](../payloads/README.md) dan
ringkasan cheat-sheet di [`oauth-cheatsheet.md`](oauth-cheatsheet.md).

## Endpoint penting

| Endpoint | Guna |
|----------|------|
| `/api/poc/<s>` (POST) | jalankan exploit otomatis skenario s1-s4 |
| `/api/toggle/<s>` (POST) | pindah mode RENTAN/FIXED |
| `/api/state` (GET) | mode aktif + sesi provider/client |
| `/logs` | attacker logs (post-mortem) |
| `/s2/login` | flow nyata S2: browser diarahkan ke `/evil/s2_capture` |
| `/evil/s2_capture` | "server penyerang" penangkap code/token |

## Privasi & keamanan

- App berjalan murni di `127.0.0.1`, data hanya di SQLite lokal (`database/lab.db`).
- Jangan pernah deploy lab ini ke internet (route `/evil/*` memang menyerupai attacker server).