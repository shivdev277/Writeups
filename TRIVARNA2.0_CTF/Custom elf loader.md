# Custom ELF Loader — TRIVARNA 2.0 (Android Reverse Engineering)

**Category:** Android / Reverse Engineering
**Difficulty:** Easy
**Points:** 100
**Flag:** `TRIVARNA{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}`

---

## Challenge Description

> The core flag logic in this application is not located in the standard `lib/<abi>/` native library folder, nor is it accessible via standard `System.loadLibrary` or `dlopen` calls. The loader locates memory via `R_*_RELATIVE` relocations, sets memory protection flags via `mprotect`, resolves dynamic symbols, and executes the payload's `get_flag()` function.
>
> Commercial packer detection tools will not identify this binary because the packer code is custom and written from scratch.

We're handed a single file: `chal05.apk`.

## TL;DR

1. Extract the APK — find an encrypted blob (`assets/payload.bin`) and a small native loader (`libstub.so`).
2. Pull the AES key/IV straight out of `libstub.so` strings.
3. Decrypt `payload.bin` with AES‑128‑CTR → recover a hidden, unstripped ARM64 ELF.
4. Disassemble its `get_flag()` function.
5. Reverse the XOR-with-rotating-key routine and the two lookup tables it uses.
6. Recompute the flag in Python.

No emulator, no Frida, no device required — this is a fully static solve.

---

## Step 1 — Recon the APK

An APK is just a ZIP file, so we start there:

```bash
unzip chal05.apk -d extracted
find extracted -type f | grep -v '^extracted/res/'
```

```
extracted/AndroidManifest.xml
extracted/classes.dex
extracted/assets/payload.bin
extracted/lib/arm64-v8a/libstub.so
extracted/resources.arsc
```

Two files stand out immediately:

| File | `file` output | Notes |
|---|---|---|
| `lib/arm64-v8a/libstub.so` | ELF 64-bit ARM aarch64, stripped | The custom "loader" |
| `assets/payload.bin` | `data` (2760 bytes) | High-entropy blob — clearly encrypted |

This matches the description perfectly: the real payload isn't a `.so` at all, it's a raw asset that `libstub.so` manually decrypts and maps into memory at runtime (a classic custom-packer / native-loader pattern).

---

## Step 2 — Extract crypto material from the loader

```bash
strings libstub.so
```

Key results:

```
Java_com_ctf_chal05_MainActivity_nativeGetFlag
AAssetManager_open
AAsset_getBuffer
payload_decrypt
aes128_encrypt_block
load_and_run
mprotect
get_flag
STUSEC_AES_KEY26
STUSEC_AES_IV_26
payload.bin
```

Two things fall out for free, with zero disassembly required:

- **AES-128 key:** `STUSEC_AES_KEY26` (16 bytes)
- **AES-128 IV/counter:** `STUSEC_AES_IV_26` (16 bytes)

The function name `aes128_encrypt_block` being used inside `payload_decrypt` is the giveaway for a **stream-cipher mode** (CTR/OFB/CFB) — in all of these, decryption is literally "encrypt the counter/IV, then XOR with the ciphertext," so the block cipher only ever needs an "encrypt" primitive.

---

## Step 3 — Decrypt the hidden ELF

Trying the stream-cipher modes against `payload.bin` with `key = iv = STUSEC_AES_KEY26 / STUSEC_AES_IV_26`:

```python
from Crypto.Cipher import AES

key = b'STUSEC_AES_KEY26'
iv  = b'STUSEC_AES_IV_26'
data = open('assets/payload.bin', 'rb').read()

cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
dec = cipher.decrypt(data)

print(dec[:4])   # b'\x7fELF'  <-- bingo
open('payload.elf', 'wb').write(dec)
```

**AES-128-CTR** produces a clean ELF header (`7F 45 4C 46`) on the first try:

```
$ file payload.elf
payload.elf: ELF 64-bit LSB shared object, ARM aarch64, version 1 (SYSV),
static-pie linked, not stripped
```

`not stripped` — meaning the challenge author left the symbol table intact. That's the "written from scratch, won't be flagged by commercial packer scanners" part of the description: it's not obfuscated, it's just *hidden* inside an encrypted asset instead of the normal `lib/` folder.

---

## Step 4 — Locate and disassemble `get_flag()`

```bash
readelf -sW payload.elf | grep get_flag
```

```
1: 0000000000001358   132 FUNC    GLOBAL DEFAULT    6 get_flag
```

Since this is a `static-pie` binary, the program headers map each segment's file offset to its virtual address with a fixed delta (e.g. `.text` is `vaddr - 0x1000 = file_offset`). Using that mapping to pull the raw bytes and disassembling with Capstone (`CS_ARCH_ARM64`) gives clean AArch64 instructions:

```python
from capstone import *

data = open('payload.elf', 'rb').read()
file_off = 0x1358 - 0x1000          # .text segment delta from readelf -lW
code = data[file_off:file_off + 132]

md = Cs(CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN)
for insn in md.disasm(code, 0x1358):
    print(f'0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}')
```

### Reading the disassembly

Boiled down, `get_flag()` does this:

```c
char buf[64];                       // lives in .bss @ 0x34a0

// 1. Write a literal prefix, byte/half/word at a time
buf[0..3] = "STUS";                 // mov/movk immediate -> 0x53555453
buf[4..5] = "EC";
buf[6]    = '{';

// 2. XOR-decode 47 bytes using two rodata tables (KEY, ENC)
//    resolved through R_AARCH64_GLOB_DAT relocations
for (i = 0; i < 47; i++) {
    idx     = (i + 7) % 14;         // division-by-multiplication trick
    buf[7+i] = KEY[idx] ^ ENC[i];
}

// 3. Close the string
buf[54] = '}';
buf[55] = '\0';
```

The `(i + 7) % 14` is implemented via the standard ARM "multiply-high-then-subtract" trick (`ubfx` → `mul` → `lsr` → `msub`) instead of an actual `sdiv`/`mod` instruction — a nice touch that makes it slightly more annoying to skim, but trivial once you recognize the pattern (constants `0x93` and `14` are the tell).

---

## Step 5 — Pull the two lookup tables

The two pointers used in the loop (`KEY` and `ENC`) aren't hardcoded addresses — they're resolved via `.rela.dyn` relocations, since this is a PIE binary:

```
$ readelf -r payload.elf

Relocation section '.rela.dyn' at offset 0x2e0 contains 2 entries:
  Offset          Type              Sym. Value    Sym. Name + Addend
  000000002490    R_AARCH64_GLOB_DAT 0000000000000310  KEY + 0
  000000002498    R_AARCH64_GLOB_DAT 0000000000000325  ENC + 0
```

Reading straight from the file at those offsets:

```python
KEY = data[0x310:0x310+14]   # b'STUSEC_ELF_KEY'
ENC = data[0x325:0x325+47]   # 47-byte ciphertext blob
```

`KEY` is a 14-byte ASCII string — which conveniently also explains the `% 14` modulus in the disassembly. `ENC` is the 47-byte encoded flag body.

---

## Step 6 — Recompute the flag

```python
KEY = b'STUSEC_ELF_KEY'
ENC = bytes.fromhex(
    '267f713914260c2063653e1a703323132a6f7f216a210b3b631a336b26'
    '27752d143668653a616430316c1a79736d7a'
)

flag_body = ''.join(chr(ENC[i] ^ KEY[(i + 7) % 14]) for i in range(47))
print('STUSEC{' + flag_body + '}')
```

Output:

```
STUSEC{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}
```

Decoded leetspeak: *"c(t)f custom elf loader no packer signature 5521"* — a fitting self-referential message given the challenge's whole premise.

`STUSEC` is the author's internal dev signature (it also shows up as the prefix of the AES key/IV strings), so per the event's flag format we submit it wrapped as:

```
TRIVARNA{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}
```

---

## Key Takeaways

- **"Custom packers" are still just encryption + a loader.** Once you find the key material (usually sitting in the loader as plaintext strings — as it was here), the "custom" packer is no harder than any other AES-encrypted blob.
- **Static-PIE binaries need offset translation.** File offset ≠ virtual address; always cross-reference `readelf -lW` before slicing raw bytes for disassembly.
- **Unstripped symbols are a gift.** Always check `readelf -sW` before diving into raw disassembly — if the challenge author left `get_flag` in the symbol table, there's no need to hunt for it manually.
- **`.rela.dyn` matters for PIE binaries.** Global data pointers (like our `KEY`/`ENC` arrays) are often zero in the raw file and only "become real" via relocations — read them directly instead of trying to execute/emulate the binary.

---

## Full Solve Script

```python
#!/usr/bin/env python3
"""
Custom ELF Loader - TRIVARNA 2.0
Full static solve: decrypt payload.bin, recompute get_flag() logic.
"""
from Crypto.Cipher import AES

# --- Step 1: decrypt the hidden ELF payload -------------------------------
key = b'STUSEC_AES_KEY26'
iv  = b'STUSEC_AES_IV_26'

payload = open('assets/payload.bin', 'rb').read()
cipher = AES.new(key, AES.MODE_CTR, nonce=b'', initial_value=iv)
elf = cipher.decrypt(payload)
assert elf[:4] == b'\x7fELF'
open('payload.elf', 'wb').write(elf)

# --- Step 2: pull KEY / ENC straight from rodata ---------------------------
# (offsets recovered from readelf -r / -sW on payload.elf)
KEY = elf[0x310:0x310 + 14]
ENC = elf[0x325:0x325 + 47]

# --- Step 3: replicate get_flag()'s XOR-with-rotating-key loop -------------
body = ''.join(chr(ENC[i] ^ KEY[(i + 7) % 14]) for i in range(47))

print(f'STUSEC{{{body}}}')
print(f'TRIVARNA{{{body}}}')
```

```
$ python3 solve.py
STUSEC{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}
TRIVARNA{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}
```

---

## Flag

```
TRIVARNA{c37f_cUs70m_3lf_l04d3r_n0_p4ck3r_s16n47ur3_5521}
```