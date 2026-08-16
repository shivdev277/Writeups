# U - Freedom Chain — TRIVARNA 2.0 (Hard, 400 pts)

**Category:** Reverse Engineering / Crypto
**Difficulty:** Hard
**Author's writeup by:** *(your name here)*

---

## TL;DR

`U - Freedom Chain` is a four-stage crackme where each stage's flag is the
decryption key for the *next* stage's artifact. Every stage is "solvable"
purely by static analysis because each verification routine is either
byte-wise independent (perfect for brute force) or a tiny custom bytecode VM
whose control flow can be disassembled by hand. The challenge plants several
decoy flags (in `strings.txt`, `flags.txt`, and dead bytecode blocks) to
punish anyone who tries to guess instead of trace the logic.

**Final flag:**
```
TRIVARNA{Tiranga_Chain_Unbroken@75!}
```

---

## Challenge Files

| File | Purpose |
|---|---|
| `chakra_vm.py` / `parade.tape` | Stage 1 verifier + encrypted artifact |
| `route_lock.py` / `sealed_route.bin` | Stage 2 verifier + encrypted artifact |
| `redfort_vm.py` / `redfort.vm` | Stage 3 verifier + encrypted bytecode |
| `ashoka_vm.py` / `ashoka.seal` | Stage 4 (final) verifier + encrypted bytecode |
| `strings.txt`, `flags.txt` | Decoy flags, red herrings |

Each `*_vm.py` script follows the same pattern:

1. Derive a SHA-256-based keystream from a **seed string + a value obtained
   from the previous stage** (a "note" or "marker").
2. XOR-decrypt the artifact with that keystream.
3. Check a magic header (`FCx!`) to confirm the key was correct.
4. Verify the user's candidate flag against a set of constraints (either
   flat per-byte records, or a tiny custom bytecode VM).
5. On success, emit a note/marker that unlocks the next stage.

This "flag → keystream → next artifact" structure is the whole point of the
challenge: you cannot skip a stage or brute force the chain out of order,
because each stage's decryption key is cryptographically tied to solving
the previous one.

---

## Stage 1 — `chakra_vm.py` + `parade.tape`

### Recon

The tape format:

```
b"U6VM1" | record_count (1 byte)
  | record_count * (index, add, xor, target)  -- 4 bytes each
  | key_len (1 byte)
  | encrypted_note (key_len bytes)
```

The verifier does this per byte of the candidate flag:

```python
def transform(byte, add, xor):
    return ((byte + add) & 0xFF) ^ xor
```

Crucially, **each record only touches one index of the candidate**, and the
transform has no dependency between bytes. That makes this trivially
invertible: for every record, brute force all 256 possible byte values and
keep the one whose `transform()` matches the target.

### Solve

```python
def transform(byte, add, xor):
    return ((byte + add) & 0xFF) ^ xor

length = max(r[0] for r in records) + 1
candidate = [None] * length
for index, add, xor, target in records:
    for b in range(256):
        if transform(b, add, xor) == target:
            candidate[index] = b
            break
```

### Result

```
flag_1      = UNI6CTF{Dawn@15_Az4d!_r1se}
route_note  = Rajpath:Gate-8|Lamp-15|Drum-47
```

`route_note` is the decryption key for Stage 2.

---

## Stage 2 — `route_lock.py` + `sealed_route.bin`

### Recon

`route_note` feeds a SHA-256-based keystream generator:

```python
key = hashlib.sha256(SEED + b"|" + route_note.encode()).digest()
```

which XOR-decrypts `sealed_route.bin` into a `FC2!`-tagged blob containing
32 records of the form `(index, mask, add, rot, target)` and a trailing
clue string. The per-byte transform:

```python
def transform(byte, index, mask, add, rot):
    mixed = (byte ^ mask) & 0xFF
    mixed = (mixed + add + index * 3) & 0xFF
    return ((mixed << rot) | (mixed >> (8 - rot))) & 0xFF
```

Still byte-independent (the `index * 3` term is a known constant per
record, not a cross-byte dependency), so the same brute-force-per-index
strategy applies directly.

### Result

```
flag_2       = UNI6CTF{Route_8x15_Drum47@N3xt!}
next_marker  = RedFort:Step-19|Bell-26|Torch-50
```

---

## Stage 3 — `redfort_vm.py` + `redfort.vm`

This is where the challenge introduces an actual **custom bytecode VM**
instead of flat records — the constraints are now embedded as executable
opcodes, and decoy flags (`strings.txt`) exist purely to bait people who
try to guess instead of decrypt.

### Disassembly

After decrypting `redfort.vm` with `next_marker`, the bytecode uses three
opcodes:

| Opcode | Meaning |
|---|---|
| `0x10 len` | Assert candidate length == `len` |
| `0x21 index mul add xor rot target` | `rol(((c[index]*mul + add + index*11) & 0xFF) ^ xor, rot) == target` |
| `0x32 i j lm rm add target` | `(c[i]*lm + c[j]*rm + add) & 0xFF == target` |
| `0x43 size note...` | Store a plaintext note to emit on success |
| `0xFF` | Accept |

All 28 `0x21` checks are independent per index → brute force each. The 4
`0x32` checks are pairwise, so they're used only as a **sanity check** after
solving the `0x21` constraints (they passed automatically since the
underlying flag is unique).

### Result

```
flag_3      = UNI6CTF{L4l_Qila@Dawn_9x!72}
final_note  = UNI6CTF{L4l_Qila@Dawn_9x!72}   (same string — emitted note == flag)
```

---

## Stage 4 — `ashoka_vm.py` + `ashoka.seal` (the real trap)

This is the "seal that binds them all together" — the decryption key is
**all three previous flags joined with `|`**:

```python
combined = f"{flag_1}|{flag_2}|{flag_3}"
```

Decrypting `ashoka.seal` with this key yields a `FC4!`-tagged bytecode
program that adds two new opcodes on top of the ones from Stage 3:

| Opcode | Meaning |
|---|---|
| `0x54 n idx... target` | Sum of `n` candidate bytes at given indices must equal `target` |
| `0x87 index parity hi lo` | If `(candidate[index] & 1) == parity`, jump to `(hi<<8)|lo` |
| `0x99 hi lo` | Unconditional jump to `(hi<<8)|lo` |

### Disassembly walkthrough

```
  4: LEN 35
  6: JMP -> 44                     ; skips a whole block of checks (idx 25,19,23,2 + pairwise)
  9-43: [DEAD CODE / DECOY]        ; never executed — matches strings.txt/flags.txt bait
 44-275: 33x CHK21 (indices 0-34 except 0 and 23)   ; mandatory, executed unconditionally
275: BRANCH idx=0  parity=1 -> 290
280: CHK21 idx=7 (decoy, conflicting target) -> JMP 350 (dead end, never reaches ACCEPT)
290: CHK21 idx=0 (real constraint on byte 0)
297: BRANCH idx=23 parity=0 -> 312
302: CHK21 idx=1 (decoy, conflicting target) -> JMP 350 (dead end, never reaches ACCEPT)
312: CHK21 idx=23 (real constraint on byte 23)
319: CHK32 (2,25) 326: CHK32 (13,19) 333: CHK32 (23,33)
340: SUM idxs=[8,0,12,34,30,31] target=11
349: ACCEPT
350: [DEAD END — no ACCEPT reachable from here]
```

**The trick:** taking the *wrong* branch at either `0x87` doesn't fail
immediately — it silently walks into a decoy `CHK21` and then jumps to a
block that can never reach the `ACCEPT` opcode (`0xFF`). A naive brute
force that ignores control flow (and just satisfies every `CHK21` it can
find in the raw byte stream) will produce a flag that *looks* structurally
valid but fails at runtime, because it never accounts for which branch is
actually reachable.

Correctly tracing the *only* reachable path to `ACCEPT` means:
- `candidate[0]` must be **odd** (parity 1),
- `candidate[23]` must be **even** (parity 0),
- plus the 33 unconditional `CHK21`s, 3 `CHK32` pairwise checks, and the
  final `SUM` check.

Solving those (again per-byte brute force for `CHK21`, then confirming
`CHK32`/`SUM` pass) gives a fully consistent 35-byte candidate.

### Result

```
final_flag = UNI6CTF{Tiranga_Chain_Unbroken@75!}
```

Verified end-to-end against the original `ashoka_vm.py`:

```
$ python3 ashoka_vm.py ashoka.seal "flag_1|flag_2|flag_3" "UNI6CTF{Tiranga_Chain_Unbroken@75!}"
correct
```

---

## Submitted Flag

The event wraps flags as `TRIVARNA{...}` rather than the internal
`UNI6CTF{...}` markers used between stages, so the final submission is:

```
TRIVARNA{Tiranga_Chain_Unbroken@75!}
```

---

## Key Takeaways

- **Chained key derivation** is a great anti-shortcut mechanism: you can't
  skip to stage 4 without correctly solving 1–3, since each stage's flag
  *is* the next stage's decryption key (directly, or hashed into one via
  SHA-256).
- **Per-byte independent constraints** (`byte + add`, `byte ^ mask`, plus a
  rotate) look intimidating but are always brute-forceable one byte at a
  time — no need for SMT solvers here.
- **Custom VM bytecode with branches** is the one place naive per-index
  brute forcing breaks down. Disassembling control flow first (jumps,
  parity branches, dead code) is essential — otherwise you'll "solve" a
  self-consistent set of constraints that never actually reaches the
  `ACCEPT` opcode.
- **Decoys are cheap and dangerous**: `strings.txt`/`flags.txt` and dead
  bytecode blocks exist specifically to reward blind guessing with a
  wrong answer that *looks* plausible. Always confirm a candidate flag
  against the real verifier before submitting.

---

## Tools Used

- Python 3 (`hashlib`, `struct`) for keystream regeneration and per-byte
  brute forcing
- Manual bytecode disassembly (simple linear/branch-aware interpreter
  loop) for the VM stages