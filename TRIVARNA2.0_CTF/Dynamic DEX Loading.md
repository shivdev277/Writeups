# Dynamic DEX Loading — TRIVARNA 2.0 (Android Reversing, Medium, 150 pts)

**Category:** Android Reverse Engineering
**Difficulty:** Medium
**Flag format:** `STUSEC{...}`

## TL;DR

The app derives an AES-256 key at runtime from its own signing certificate hash and its
`classes.dex` CRC32 (via HKDF-SHA256), uses that key to AES-GCM decrypt a second DEX hidden in
`assets/`, and loads it with `InMemoryDexClassLoader`. The second-stage DEX gates flag generation
behind native anti-debug / anti-hook checks — but those checks are cosmetic, since the flag
value itself is a hardcoded byte array XOR'd with a static keystream and never actually depends
on the derived key or on the checks passing. The whole challenge can be solved with pure static
analysis, no emulator, device, or Frida required.

**Flag:** `STUSEC{dYn4m1c_d3x_l04d1ng_4nd_4r7_4n71_d3bu6_byp4ss_7382}`

---

## 1. Recon

The challenge ships a single `chal02.apk`. First pass, unzip it and see what's inside:

```bash
unzip -l chal02.apk
```

```
AndroidManifest.xml
classes.dex
assets/stage2.dex.enc
lib/arm64-v8a/libantidebug.so
lib/armeabi-v7a/libantidebug.so
lib/x86/libantidebug.so
lib/x86_64/libantidebug.so
resources.arsc
...
```

Two things jump out immediately:

- `assets/stage2.dex.enc` — an encrypted payload, clearly a second DEX given the filename.
- `libantidebug.so` — a native library, present for all four ABIs, hinting at native anti-debug
  checks gating something.

This is the classic **"loader decrypts and dynamically loads a hidden DEX"** pattern, combined
with anti-tampering. Package name from the manifest: `com.ctf.chal02`.

## 2. Decompiling stage 1

```bash
apktool d -r chal02.apk -o apktool_out      # baksmali + manifest, skip broken resources.arsc
jadx -d jadx_out chal02.apk                 # Java-level decompile for readability
```

`jadx` decompiled cleanly. Four custom classes matter:

- `MainActivity` — entry point, kicks off the loader on a background thread.
- `IntegrityGate` — derives the AES key from cert hash + DEX CRC32.
- `DexKeyDerivation` — a hand-rolled HKDF-SHA256 implementation.
- `Stage2Loader` — reads, AES-GCM decrypts, and `InMemoryDexClassLoader`s the hidden DEX.

### 2.1 `MainActivity`

```java
final String result = Stage2Loader.INSTANCE.loadAndExecute(
        this, IntegrityGate.INSTANCE.deriveKey(this));
```

Straightforward: derive a key, hand it to the stage-2 loader, display whatever string comes back.

### 2.2 `IntegrityGate.deriveKey()` — where the AES key comes from

```java
public final byte[] deriveKey(Context context) {
    byte[] ikm  = getCertSha256(context) + getDexCrc32(context);   // 32 + 4 = 36 bytes
    byte[] salt = "STUSEC_SALT_2026".getBytes(UTF_8);
    byte[] info = "DEX_DEC_KEY".getBytes(UTF_8);
    return DexKeyDerivation.INSTANCE.hkdf(salt, ikm, info, 32);
}
```

- `getCertSha256()` — SHA-256 of the app's own signing certificate (`SigningInfo.getApkContentsSigners()[0]`).
- `getDexCrc32()` — the CRC32 of the `classes.dex` zip entry, taken straight from the `ZipEntry`
  metadata (no hashing needed — it's already stored in the APK's central directory), packed as
  4 big-endian bytes.

This is a lightweight **integrity binding**: if you re-sign the APK with a different key, or
patch `classes.dex` (changing its CRC), the derived key changes and stage 2 fails to decrypt.
Neither value is secret, though — both are trivially recoverable from the APK file itself without
running anything on a device.

### 2.3 `DexKeyDerivation.hkdf()`

A textbook two-step HKDF: `HMAC-SHA256(salt, ikm)` for the *extract* step, followed by the
standard *expand* loop (`T(i) = HMAC(prk, T(i-1) || info || i)`), truncated to 32 bytes. Nothing
non-standard here — it matches RFC 5869 exactly, which made re-implementing it in Python trivial.

### 2.4 `Stage2Loader`

```java
byte[] plaintext = decryptGcm(assets.open("stage2.dex.enc").readBytes(), aesKey);
new InMemoryDexClassLoader(ByteBuffer.wrap(plaintext), context.getClassLoader())
        .loadClass("com.ctf.chal02.s2.EntryPoint")
        .getDeclaredMethod("run", Context.class, byte[].class)
        .invoke(null, context, aesKey);
```

`decryptGcm` treats the first **12 bytes** of the asset as the GCM IV and the rest as
ciphertext + 16-byte auth tag, decrypting with `AES/GCM/NoPadding` under the derived key. This
confirms the file format: `IV(12) || CIPHERTEXT || TAG(16)`.

## 3. Recovering the key statically

Both integrity inputs can be pulled from the APK **without installing or running it**.

**Signing certificate SHA-256** (v2 signing block, via `androguard`):

```python
from androguard.core.apk import APK
import hashlib

a = APK('chal02.apk')
cert_der = a.get_certificates_der_v2()[0]
cert_sha256 = hashlib.sha256(cert_der).digest()
```

**`classes.dex` CRC32** (already stored in the zip's central directory — no need to recompute it):

```python
import zipfile

crc = zipfile.ZipFile('chal02.apk').getinfo('classes.dex').CRC
crc_bytes = crc.to_bytes(4, 'big')
```

**HKDF re-implementation:**

```python
import hmac, hashlib

def hkdf(salt, ikm, info, length):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    t, okm, i = b"", b"", 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]

key = hkdf(
    salt=b"STUSEC_SALT_2026",
    ikm=cert_sha256 + crc_bytes,
    info=b"DEX_DEC_KEY",
    length=32,
)
```

## 4. Decrypting stage 2

```python
from Crypto.Cipher import AES

data = open('assets/stage2.dex.enc', 'rb').read()
iv, ct, tag = data[:12], data[12:-16], data[-16:]

cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
plaintext = cipher.decrypt_and_verify(ct, tag)   # raises on bad tag/key
open('stage2.dex', 'wb').write(plaintext)
```

The GCM tag verified on the first try — solid confirmation the key derivation logic (and the
statically-recovered cert hash / CRC) was correct. `stage2.dex` is a valid Dalvik `.dex`
(version `037`).

## 5. Analyzing stage 2

```bash
jadx -d stage2_jadx stage2.dex
```

Four classes: `EntryPoint`, `AntiDebug`, `AntiHook`, `FlagTransform`.

```java
public static String run(Context context, byte[] key) {
    if (AntiDebug.check() && AntiHook.check()) {
        return FlagTransform.deriveFlag(key);
    }
    return null;
}
```

- `AntiDebug.check()` → native `nativePtraceCheck()` in `libantidebug.so` (standard
  `PTRACE_TRACEME`-style debugger detection).
- `AntiHook.check()` → scans `/proc/self/maps` for `frida`, `gadget`, `xposed`, `substrate`.

These look like the "real" gate the challenge wants you to bypass at runtime (patch out the
checks, run under Frida with anti-anti-debug tricks, etc.). But reading `FlagTransform` shows
they're a **red herring for static analysis**:

```java
private static final byte[] MAGIC = {0x5A, 0x53, 0x00, 0x01};
private static final byte[] ROLL  = "STUSEC_ROLL_2026".getBytes(UTF_8);
private static final byte[] SEED  = { /* 54 hardcoded bytes, MAGIC-prefixed */ };

public static String deriveFlag(byte[] key) {          // <-- key parameter is unused
    byte[] body = Arrays.copyOfRange(SEED, MAGIC.length, SEED.length);
    byte[] out  = new byte[body.length];
    for (int i = 0; i < body.length; i++) {
        out[i] = (byte) (body[i] ^ ROLL[i % ROLL.length]);
    }
    return "STUSEC{" + new String(out, UTF_8) + "}";
}
```

The derived AES key is passed into `deriveFlag` but never referenced — the flag is a **static
XOR-obfuscated constant** baked into the DEX, only gated by two runtime checks that never
influence *what* the flag is, only *whether* it's printed. Since we already have the raw bytes
via static decompilation, we don't need to satisfy `AntiDebug`/`AntiHook` at all.

## 6. Extracting the flag

```python
SEED = bytes([0x5A,0x53,0x00,0x01, 0x37,0x0D,0x3B,0x67,0x28,0x72,0x3C,0x0D,0x2B,0x7F,0x34,0x00,
              0x5E,0x00,0x06,0x52,0x62,0x3A,0x32,0x0C,0x71,0x2D,0x3B,0x0D,0x7B,0x3E,0x7B,0x00,
              0x06,0x5E,0x05,0x07,0x0C,0x30,0x66,0x31,0x30,0x75,0x00,0x30,0x36,0x3C,0x78,0x2C,
              0x41,0x6F,0x05,0x05,0x6B,0x66])
MAGIC = bytes([0x5A, 0x53, 0x00, 0x01])
ROLL  = b"STUSEC_ROLL_2026"

body = SEED[len(MAGIC):]
out  = bytes(b ^ ROLL[i % len(ROLL)] for i, b in enumerate(body))
print("STUSEC{" + out.decode() + "}")
```

```
STUSEC{dYn4m1c_d3x_l04d1ng_4nd_4r7_4n71_d3bu6_byp4ss_7382}
```

## 7. Flag

```
STUSEC{dYn4m1c_d3x_l04d1ng_4nd_4r7_4n71_d3bu6_byp4ss_7382}
```

---

## Tooling used

| Tool | Purpose |
|---|---|
| [`apktool`](https://ibotpeaches.github.io/Apktool/) | Baksmali disassembly / manifest inspection |
| [`jadx`](https://github.com/skylot/jadx) | Java-level decompilation of both DEX stages |
| [`androguard`](https://github.com/androguard/androguard) | Parsing the APK v2 signing block to recover the signer certificate |
| Python 3 + `pycryptodome` | Reimplementing HKDF-SHA256 and AES-GCM decryption |

## Key takeaways

1. **"Runtime-derived" doesn't mean "attacker can't derive it."** Both integrity check inputs
   (signing cert hash, DEX CRC32) are public data embedded in the APK file itself — they only
   protect against *tampering*, not against *disclosure*. Anything computable from a file you
   already have is computable offline.
2. **Follow the data, not the control flow.** The native anti-debug/anti-hook checks look like
   the intended obstacle, but tracing what `deriveFlag()` actually consumes shows the checks
   never touch the flag bytes. A control-flow gate around a static computation is not the same
   as the computation depending on that gate — reading the sink first can save you from reversing
   a native library entirely.
3. Dynamic DEX loading (`InMemoryDexClassLoader`) is transparent to static analysis as long as
   you can recover the decryption key — you don't need a rooted device or Frida to see what code
   actually runs.

---

*Writeup for TRIVARNA 2.0 — "Dynamic DEX Loading" (150 pts, Medium).*