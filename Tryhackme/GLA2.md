# Grand Larceny Auto II — TryHackMe Writeup

**Category:** Reverse Engineering / Web API Exploitation
**Difficulty:** Medium
**Skills:** Static binary analysis, .NET/IL disassembly, HTTP API reverse engineering, HMAC signature abuse, business logic flaws

---

## 1. Challenge Overview

*Grand Larceny Auto II* ships as a standalone game client rather than a typical web or binary pwn target. The room's premise is that the "vault" visible inside the game is a decoy — the real objective is not reachable through normal gameplay. To get the actual flag, you have to:

1. Pull apart the shipped game client to understand how it authenticates with its backend.
2. Reverse engineer the client/server protocol it uses.
3. Identify a logic flaw in that protocol.
4. Interact with the live backend directly (bypassing the game entirely) to obtain the real flag.

This writeup covers the full process: static analysis, protocol recovery, vulnerability identification, and exploitation — without including the flag itself or the exact internal paths that lead to it.

---

## 2. Environment Setup

- Attacking machine: Kali Linux (VM), connected to the THM lab network via OpenVPN.
- Target resolved via a static hosts entry, since the game hardcodes a friendly hostname rather than an IP:

  ```
  <LAB_IP>    gla2.thm
  ```

- Connectivity was verified with `curl` and `ping` before touching the game files. A `404` on `/` from a `Kestrel` server banner confirmed the backend is a .NET (ASP.NET Core) application, which turned out to be consistent with what the client binary revealed later.

---

## 3. Static Analysis of the Game Client

The distributed archive contained both Linux and Windows builds of the game. The game itself is built on the **Godot** engine using **C#/.NET**, which meant the actual game logic lives in a managed assembly rather than being fully compiled into the native engine binary.

### 3.1 Locating the relevant assembly

Inside the Linux build's data directory, alongside the standard Godot/.NET runtime DLLs (`GodotSharp.dll`, `mscorlib`, etc.), there was a single game-specific assembly containing all of the project's own C# code. This is the assembly of interest — everything else is stock engine/runtime code.

### 3.2 String extraction

Running both ASCII and UTF-16LE string extraction against the assembly immediately surfaced a number of interesting artifacts:

- A hardcoded base URL for a backend service.
- Class and method names strongly suggestive of a client/server "proof of play" workflow (session handling, checkpoint reporting, a signing/keying routine, and a "claim" step).
- JSON key fragments (`"role"`, `"token"`) embedded as literal string constants, indicating the client builds and sends structured JSON payloads.
- A separate, unrelated set of vault-related class/method names tied to **local, in-game** logic — this turned out to be the decoy single-player vault mechanic the room description explicitly warns is a dead end.

### 3.3 Disassembling the managed assembly

With no full .NET decompiler readily available in the working environment, the assembly was disassembled to CIL (Common Intermediate Language) instead. CIL disassembly is verbose but fully readable line-by-line, and for straightforward business logic like this it's entirely sufficient to reconstruct the original algorithm by hand.

From the disassembly, a networking class emerged that:

- Defines the backend base URL.
- Wraps `HttpClient` calls into three named operations.
- Contains a static signing key used with HMAC-SHA256.
- Builds and parses JSON payloads for each operation.
- Contains **one method that computes a value but is never actually called anywhere else in the assembly** — a strong signal that it was left in deliberately as a puzzle piece rather than removed as dead code.

---

## 4. Protocol Recovery

Reconstructing the disassembly line-by-line produced a clear picture of a three-endpoint REST-style protocol:

| Step | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST /session` | Opens a new play session; returns a token, a session identifier, and an ordered list of values that dictate the required sequence of in-game "checkpoints." |
| 2 | `POST /checkpoint` | Reports completion of a specific step in that sequence. Must be called once per step, **in the exact order the server specified**, each carrying a signature and the current token. |
| 3 | `POST /claim` | Submits a role and requests the final reward for the session once all checkpoints are satisfied. |

### 4.1 Request signing

Every state-changing request includes a `sig` field computed as:

```
sig = hex( HMAC_SHA256( key, message ) )
```

Where the signing key is a static string embedded directly in the client binary, and the message format differs slightly per endpoint (it incorporates the session identifier, the current token, and — for checkpoints — the step name being reported).

### 4.2 Session/token behavior discovered during testing

Two behaviors were **not** obvious from the static analysis alone and only surfaced once live requests were sent to the server:

- **Rate limiting** — the backend enforces a minimum delay between consecutive actions on a session. Requests sent too quickly are rejected with an HTTP `425 Too Early` response that helpfully reports the required interval, making it trivial to self-correct client-side.
- **Token rotation** — every successful response issues a *new* token that must be used for the next request. Reusing a stale token results in an HTTP `401 Unauthorized`. This mirrors a one-time-token / nonce pattern and had to be handled by updating local state after every response.

Both behaviors are consistent with basic anti-automation/anti-replay measures, and both are easily satisfied once identified — they don't meaningfully block a scripted client, they just have to be respected.

---

## 5. The Vulnerability

The critical finding is in how the `/claim` request is signed. The signature only binds together:

- The session identifier
- A fixed literal indicating the "claim" action
- The current token

**The role value submitted in the same request is never included in the signed message.** The legitimate game client always hardcodes a single, low-privilege role string when it calls this endpoint — but because that field sits outside the integrity check, nothing on the server side stops a client from substituting a different value while keeping the rest of the request (and its now-valid signature) untouched.

This is a classic **broken access control / insufficient message integrity** flaw: the server treats a signed request as fully trustworthy, but the signature doesn't actually cover every field that influences the server's authorization decision.

### 5.1 The missing piece was in the binary all along

The "unused" method identified during disassembly turned out to compute exactly the kind of value the server expects for an elevated role: a SHA-1 hash built by concatenating the entire checkpoint sequence for the session (the fixed starting step, each of the ordered values returned by `/session`, and the fixed final step) into one string, then hashing it.

In other words, the developers left the *derivation logic* for a privileged role sitting in the shipped client, presumably for internal QA/testing purposes, and simply never wired it into the release build's UI. Reverse engineering the binary was enough to recover it.

---

## 6. Exploitation

The full exploit chain, performed with a standalone script talking directly to the backend (no game client involved):

1. **Open a session** — `POST /session` with an empty body. Store the returned token, session ID, and the ordered checkpoint values.
2. **Walk the checkpoint chain** — for each required step, in the order dictated by the server:
   - Compute the HMAC signature for that step using the current token.
   - Submit it to `/checkpoint`.
   - Respect the server's rate limit (or just retry automatically using the `need`/`got` values it returns on a `425`).
   - Update the stored token from the response before the next request.
3. **Derive the privileged role value** — reconstruct the same string the dead-code method builds (start step + each checkpoint value + end step, concatenated) and hash it with SHA-1.
4. **Submit the claim** — `POST /claim` with a valid signature (still only covering session ID, the claim literal, and the current token) but with the **derived role** in place of the client's normal hardcoded value.
5. **Read the response** — the backend returns the reward payload for the session directly in the JSON body.

The entire interaction can be done with nothing more than a scripting language's standard HTTP and cryptographic hashing libraries — no game engine, no memory patching, and no interaction with the actual game client was required once the protocol and signing scheme were understood.

---

## 7. Root Cause & Lessons

- **Client-side secrets aren't secret.** The HMAC key was embedded directly in a distributable binary. Anyone with the client can extract it and forge arbitrarily many valid signatures.
- **Partial message signing is as dangerous as no signing.** Authenticating *some* fields in a request while leaving an authorization-relevant field (`role`) outside the signature defeats the purpose of signing in the first place. Every field that affects a trust decision needs to be covered by the integrity check.
- **Dead code ships too.** Leftover developer/QA logic compiled into a release build is still fully readable by anyone willing to disassemble it. If a code path shouldn't be reachable in production, it shouldn't exist in the shipped artifact at all — obscurity via "the UI doesn't expose it" is not a control.
- **Rate limiting and token rotation are good practices, but not a substitute for correct authorization logic.** Both were present here and both were trivially satisfiable by a compliant scripted client; they slowed down brute-force/replay abuse but did nothing to stop a logic flaw once it was understood.

---

## 8. Tools Used

- `7z` / `unzip` — archive extraction
- `strings` (ASCII and UTF-16LE modes) — quick artifact discovery in the managed assembly
- `monodis` (Mono CIL disassembler) — full method-level disassembly of the .NET assembly
- Python 3 standard library (`hmac`, `hashlib`, `json`, `urllib.request`) — protocol reimplementation and exploitation
- `curl` / `ping` — connectivity verification against the lab target

---

## 9. Conclusion

This challenge is a good example of why "the flag isn't in the game" doesn't mean the game is irrelevant — the client binary *is* the documentation for an otherwise undocumented API, including, in this case, a leftover method that all but hands you the intended solution once you know where to look. Combining basic static reverse engineering with careful HTTP protocol reconstruction was enough to fully bypass the intended progression and reach the real, developer-tier reward directly.

*Flag intentionally omitted from this writeup.*
