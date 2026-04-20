# SecureHub — Live Demo Script (15–20 min Video)

## Prerequisites

```bash
# Start the application
docker compose up --build

# Open browser: https://localhost (accept self-signed certificate)
# Open a terminal for curl commands and database inspection
```

---

## Part 1: Architecture Overview (2–3 min)

Present the system architecture from `README.md`:

1. **Frontend**: Avalonia UI compiled to WebAssembly, runs entirely in the browser
2. **Nginx**: TLS termination with self-signed certificate, HTTP→HTTPS 301 redirect, HSTS header
3. **Backend**: .NET 10 Minimal API behind Nginx reverse proxy (`/api/` → Kestrel on port 8080)
4. **Encryption Layer**: AES-256 file encryption at rest, BCrypt password hashing, EF Core field-level AES ValueConverters
5. **STRIDE Threat Model**: Walk through the 6-category threat defense table from the Report

---

## Part 2: Live Demonstration (8–10 min)

### 2.1 User Registration + Password Hashing

1. Open `https://localhost` and click **Register**
2. Create a new account: `demo@test.com` / `Passw0rd#2026`
3. After registration, switch to the terminal:

```bash
# Prove passwords are never stored in plaintext
sqlite3 ./data/db/app.db "SELECT Email, PasswordHash FROM Users;"
```

**Talking Point:** *"Passwords are hashed using BCrypt with a cost factor of 13. Even if the database is compromised, the attacker cannot reverse the hash to obtain the original password."*

---

### 2.2 File Upload + Encryption at Rest Verification

1. Log in as `demo@test.com`
2. Click **📁 Click to Select File** and upload a `.txt` or `.pdf` file
3. Switch to terminal:

```bash
# List encrypted files (UUID-named, no original filenames exposed)
ls -la ./data/storage/

# Hexdump the encrypted file to prove it is unreadable ciphertext
hexdump -C ./data/storage/<UUID>.dat | head -20
```

4. Go back to the browser and click **Download** — open the file to verify it decrypts correctly

**Talking Point:** *"Files are encrypted on-the-fly using AES-256 before being written to disk. The physical storage contains only ciphertext. Decryption happens in a streaming fashion when an authorized user requests a download through the API."*

---

### 2.3 Shareable Links (Expiry + Password Protection)

1. Find the uploaded file in the file list
2. Click **Share**
3. Configure:
   - Permission: `Download`
   - Expiry: `1 Hour`
   - Password: `share123`
4. Copy the generated share link
5. Open an **Incognito/Private** browser window, paste the link
6. Show the password prompt; enter the correct password to download

**Talking Point:** *"Share links use cryptographically random GUID tokens — they cannot be guessed. Each link supports optional expiry times and password protection, giving users granular control over shared access."*

---

### 2.4 Attack Simulation: XSS Injection (Blocked)

Attempt to inject script via a filename or search input:

```
<script>alert('XSS')</script>
```

**Expected Result:** The input is safely escaped and displayed as plain text — no JavaScript executes.

**Talking Point:** *"Avalonia WASM renders UI via a compiled C# engine, not the DOM. There is no innerHTML manipulation, making DOM-based XSS structurally impossible."*

---

### 2.5 Attack Simulation: IDOR (Blocked)

```bash
# Step 1: Log in as demo@test.com and get the session cookie
curl -k -c cookies.txt -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@test.com","password":"Passw0rd#2026"}'

# Step 2: Attempt to download a file owned by another user (ID guessing)
curl -k -b cookies.txt -w "\nHTTP Status: %{http_code}\n" \
  https://localhost/api/files/download/999
```

**Expected Result:** `404 Not Found` (not `403 Forbidden` — to avoid leaking that the resource exists)

**Talking Point:** *"Every file access request checks `OwnerId == RequestingUserId` at the database level. Even if an attacker guesses a valid file ID, the server returns 404 — identical to a non-existent file — preventing information disclosure."*

---

### 2.6 Attack Simulation: Brute-Force Login (Rate Limited)

```bash
# Send 6 rapid login attempts (limit is 5 per minute)
for i in {1..6}; do
  STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" -X POST \
    https://localhost/api/auth/login \
    -H "Content-Type: application/json" \
    -d '{"email":"demo@test.com","password":"wrongpassword"}')
  echo "Attempt $i: HTTP $STATUS"
done
```

**Expected Result:**
```
Attempt 1: HTTP 401
Attempt 2: HTTP 401
Attempt 3: HTTP 401
Attempt 4: HTTP 401
Attempt 5: HTTP 401
Attempt 6: HTTP 429    ← Rate limited!
```

**Talking Point:** *"A Fixed Window Rate Limiter restricts each IP to 5 login attempts per minute. The 6th attempt receives a 429 Too Many Requests response, effectively neutralizing automated brute-force tools."*

---

### 2.7 Audit Log Inspection

1. Log in as **Admin**: `admin@securehub.local` / `AdminSecur3#1024!`
2. Navigate to the Admin panel → **Audit Logs**
3. Show the recorded events: logins, uploads, downloads, shares, failed login attempts

```bash
# Alternative: query via curl
curl -k -c cookies.txt -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@securehub.local","password":"AdminSecur3#1024!"}'

curl -k -b cookies.txt https://localhost/api/admin/audit-logs
```

**Talking Point:** *"The AuditLogMiddleware records who, what, when, and from where for every security-relevant action. This addresses the Repudiation threat from our STRIDE analysis — users cannot deny performing an action."*

---

### 2.8 Account Deletion (GDPR Compliance)

1. Log back in as `demo@test.com`
2. Click **Delete Account**
3. Enter password to confirm
4. Verify in terminal:

```bash
# Confirm user removed from database
sqlite3 ./data/db/app.db "SELECT * FROM Users WHERE Email='demo@test.com';"
# Expected: empty result

# Confirm encrypted files are physically deleted
ls -la ./data/storage/
# Expected: the user's file is gone
```

**Talking Point:** *"This satisfies the GDPR 'Right to Erasure' and PIPEDA consent withdrawal. Deletion is cascading — the database record, all physical encrypted files, and all share links are permanently purged. This is not a soft-delete."*

---

### 2.9 Malicious File Upload Rejection (Phase 3 Task 3.2)

```bash
# Test A: Upload a .exe file → should be rejected
curl -k -b cookies.txt -X POST https://localhost/api/files/upload \
  -F "file=@malware.exe"

# Test B: Upload a double-extension file → should be rejected
# First create the test file:
echo "fake payload" > "malware.pdf.exe"
curl -k -b cookies.txt -X POST https://localhost/api/files/upload \
  -F "file=@malware.pdf.exe"

# Test C: Upload an oversized file (>10MB) → should be rejected
dd if=/dev/zero of=bigfile.txt bs=1M count=12
curl -k -b cookies.txt -X POST https://localhost/api/files/upload \
  -F "file=@bigfile.txt"
```

**Expected Result:** All three return `400 Bad Request` with rejection messages (blocked MIME type / invalid extension / file too large).

**Talking Point:** *"The server validates both the MIME type and file extension against an allowlist. Double extensions like `.pdf.exe` are caught because the final extension is checked. File size is enforced at both the Nginx level (15MB) and the application level (10MB)."*

---

### 2.10 RBAC — Unauthorized Admin Access (Phase 4 Task 4.1)

```bash
# Log in as a regular user
curl -k -c cookies.txt -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"demo@test.com","password":"Passw0rd#2026"}'

# Attempt to access admin-only audit logs
curl -k -b cookies.txt -w "\nHTTP Status: %{http_code}\n" \
  https://localhost/api/admin/audit-logs
```

**Expected Result:** `403 Forbidden` — the server enforces role checks server-side, not just by hiding UI elements.

**Talking Point:** *"Access control is enforced at the API level, not the UI. Even if someone bypasses the frontend and calls the admin endpoint directly via curl or Postman, the server rejects the request unless the JWT contains the Admin role claim."*

---

### 2.11 HTTPS Padlock + Certificate Details (Phase 5 Task 5.2)

1. In the browser, click the **🔒 padlock icon** (or "Not Secure" for self-signed) in the address bar
2. Click **"Certificate"** to show the certificate details:
   - Issuer: `SecureHub`
   - Subject: `CN=localhost`
   - Validity: 365 days
3. Open DevTools (F12) → **Network** tab → select any request → show **Security** tab
4. Show the `Strict-Transport-Security` header in the response headers

**Talking Point:** *"All traffic is encrypted via TLS. The HSTS header with max-age=31536000 instructs browsers to always use HTTPS for future visits, preventing SSL downgrade attacks."*

---

### 2.12 Generic Error Page — No Stack Traces (Phase 7 Task 7.1)

```bash
# Trigger a server error by sending malformed JSON to a valid endpoint
curl -k -b cookies.txt -X POST https://localhost/api/files/share \
  -H "Content-Type: application/json" \
  -d '{"invalid json'
```

**Expected Result:** A generic JSON error like `{"error": "An unexpected error occurred."}` — **NOT** a .NET stack trace or exception details.

**Talking Point:** *"In production mode, GlobalExceptionHandlerMiddleware catches all unhandled exceptions and returns a sanitized error message. Stack traces, class names, and internal paths are never exposed to the client, denying attackers reconnaissance information."*

---

### 2.13 Dependency Security Audit (Phase 7 Task 7.2)

```bash
# Run NuGet vulnerability scan on the API project
dotnet list SecureHub.Api/SecureHub.Api.csproj package --vulnerable

# Run on the Client project
dotnet list SecureHub.Client/SecureHub.Client/SecureHub.Client.csproj package --vulnerable
```

**Expected Result:** `No vulnerable packages found` (or show a previously resolved vulnerability and explain how it was patched).

**Talking Point:** *"Regular dependency auditing is critical even when no vulnerabilities are found. New CVEs are discovered daily — a dependency that was safe yesterday may be compromised tomorrow. Automated scans should be part of every CI/CD pipeline."*

---

## Part 3: Security Controls Deep Dive (3–4 min)

Walk through the 7 security features from the Report:

1. **Why BCrypt over SHA-256?** — BCrypt has a configurable cost factor that makes it intentionally slow, defeating GPU-accelerated cracking
2. **Why HttpOnly cookies for JWT?** — Prevents JavaScript from reading the token, neutralizing XSS-based session hijacking
3. **Why UUID file names?** — Prevents path traversal attacks (`../../etc/passwd`) and hides the original filename from storage inspection
4. **Why non-root Docker user?** — If the container is compromised, the attacker has limited privileges
5. **Why Nginx for TLS instead of Kestrel?** — Nginx is hardened for production TLS, supports HSTS, and centralizes certificate management

---

## Part 4: Lessons Learned (2–3 min)

Suggested talking points:

1. **Hardest security control to implement:** AES-256 streaming encryption — had to process large files in O(1) memory using CryptoStream without loading entire files into memory
2. **What we would do differently:** Replace SQLite with PostgreSQL for horizontal scalability; use AWS KMS for encryption key management instead of environment variables
3. **Key takeaway:** Security is not a bolt-on layer — starting with STRIDE threat modeling ensured that security controls were designed as architecture fundamentals, not afterthoughts

---

## Quick Reference: curl Commands

```bash
# Login
curl -k -c cookies.txt -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@securehub.local","password":"AdminSecur3#1024!"}'

# List files
curl -k -b cookies.txt https://localhost/api/files

# Upload file
curl -k -b cookies.txt -X POST https://localhost/api/files/upload \
  -F "file=@/path/to/test.pdf"

# Create share link
curl -k -b cookies.txt -X POST https://localhost/api/files/share \
  -H "Content-Type: application/json" \
  -d '{"fileId":1,"permission":"Download","expiryHours":24,"password":"secret"}'

# Access share link
curl -k "https://localhost/api/files/shared/<TOKEN>?pwd=secret"

# View audit logs (Admin only)
curl -k -b cookies.txt https://localhost/api/admin/audit-logs

# Delete account
curl -k -b cookies.txt -X DELETE https://localhost/api/users/me \
  -H "Content-Type: application/json" \
  -d '{"password":"Passw0rd#2026"}'
```
