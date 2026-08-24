# Free Play — BrunnerCTF 2026 (Forensics, 100 pts)

**Category:** Forensics
**Difficulty:** Easy–Medium
**Author:** Quack
**Flag:** `brunner{strong_force_in_you}`

## Challenge Description

> IT flagged a workstation during an asset audit and found that someone from Procurement had installed some game from 2009 on his corporate laptop. Apparently, he was obsessed with the game and had been "working from home" for three weeks, seemingly just staring at his character roster.
>
> HR wants to know what he was doing, and luckily recovered his save file along with a screenshot from the backup share. Go figure out what is so special about this save file.

**Handout:** `forensics_free-play.zip`, containing:
- `Game.jpg` — a screenshot of a character-select screen
- `SaveGame1` — a binary save file

## TL;DR

The save file is from **LEGO Star Wars: The Complete Saga**. Hidden inside the custom-character creator data is a 156-byte array where every byte is either `0x00` or `0x03`. Reinterpreting that as a bitstream (`0x00 → 0`, `0x03 → 1`) and grouping it into bytes decodes cleanly to ASCII:

```
strong_force_in_you
```

Flag: `brunner{strong_force_in_you}`

## Step 1 — Initial Triage

Unzipping the handout gives two files:

```
$ unzip -l forensics_free-play.zip
  forensics_free-play/SaveGame1
  forensics_free-play/Game.jpg
```

`Game.jpg` is a screenshot of the character-select screen from **LEGO Star Wars: The Complete Saga** (2009) — this confirms the game and gives useful visual context (which slots are unlocked vs. locked), though it turns out not to be strictly required to recover the flag.

`SaveGame1` is flagged as raw `data` by `file`:

```
$ file SaveGame1
SaveGame1: data
```

A quick hex dump shows it opens with the magic bytes `HMGR`:

```
00000000  48 4d 47 52 01 00 00 00 28 20 00 00 00 00 00 00  HMGR....( ......
```

`HMGR` is the header used by Traveller's Tales' internal reflection/serialization format, which they reused across most of their LEGO titles of that era to store save data as a tree of typed, named fields.

I checked `Game.jpg` for any appended data or EXIF steganography (trailing bytes after the JPEG `FFD9` EOI marker, unusual metadata) — nothing was hidden there. The image is scene-setting only; the interesting artifact is the save file itself.

## Step 2 — Baseline String Analysis

The game stores most of its internal strings as UTF-16LE, so a plain `strings` pass on `SaveGame1` misses almost everything. Extracting both ASCII and UTF-16LE strings:

```bash
strings -n 3 SaveGame1                # ASCII
strings -e l -n 3 SaveGame1           # UTF-16LE
```

This surfaces entirely legitimate game internals — level data filenames, input glyphs, and sound-cue identifiers:

```
Episode_I.DAT ... Episode_VI.DAT
[TOGGLERIGHT] [TOGGLELEFT] [CROSS] [JUMP] [CIRCLE] [SPECIAL] [SQUARE] [ACTION] [TRIANGLE] [TAG]
DONT_JUMP_NOW  JUMP_NOW  OBSTACLE  FORBADDIES  FORGOODIES  HOVERTUBE  USEHATCH  GRAPPLE
wpn_bib_stab  wpn_axe_swing  GunShot  PodX_TuskenBlast  imp_impacts  imp_proton_torp
```

Two more interesting strings stand out — the default names of the two **custom character** slots created via the game's in-game character builder ("Cantina" creator):

```
STRANGER 1
STRANGER 2
```

These are the placeholder names the game assigns to a custom minifigure until the player renames it — meaning our subject built (at least) one custom character but never bothered to rename it. This is the thread worth pulling.

## Step 3 — Entropy Sweep

Before diving deeper, I ran an entropy check across the file in 512-byte blocks to rule out an encrypted or compressed blob hiding somewhere:

```python
def entropy(b):
    from collections import Counter
    import math
    c = Counter(b)
    n = len(b)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

for i in range(0, len(data), 512):
    block = data[i:i+512]
    e = entropy(block)
    if e > 3:
        print(i, round(e, 2))
```

Nothing came back with high entropy — whatever was hidden here wasn't XOR'd, compressed, or encrypted. It had to be hidden *structurally*, in plain sight within otherwise legitimate-looking save data.

## Step 4 — Finding the Anomaly

I scanned for long contiguous runs of low-cardinality byte values — a good heuristic for spotting hand-crafted bitmasks or flag arrays sitting inside otherwise "normal" binary noise:

```python
i = 0
runs = []
while i < len(data):
    if data[i] in (0, 1, 2, 3):
        j = i
        while j < len(data) and data[j] in (0, 1, 2, 3):
            j += 1
        if j - i > 50:
            runs.append((i, j, j - i))
        i = j
    else:
        i += 1
```

This turned up a handful of candidates, but one was immediately suspicious: a **156-byte block sitting directly after the `STRANGER 1` / `STRANGER 2` name fields**, where *every single byte* is either `0x00` or `0x03`:

```
009d20  00 03 03 03 00 00 03 03 00 03 03 03 00 03 00 00
009d30  00 03 03 03 00 00 03 00 00 03 03 00 03 03 03 03
009d40  00 03 03 00 03 03 03 00 00 03 03 00 00 03 03 03
009d50  00 03 00 03 03 03 03 03 00 03 03 00 00 03 03 00
009d60  00 03 03 00 03 03 03 03 00 03 03 03 00 00 03 00
009d70  00 03 03 00 00 00 03 03 00 03 03 00 00 03 00 03
009d80  00 03 00 03 03 03 03 03 00 03 03 00 03 00 00 03
009d90  00 03 03 00 03 03 03 00 00 03 00 03 03 03 03 03
009da0  00 03 03 03 03 00 00 03 00 03 03 00 03 03 03 03
009db0  00 03 03 03 00 03 00 03
```

Structurally, this lines up with the part of the save format that tracks which cosmetic parts are equipped on a custom character. But two-value, hand-alternating data like this — sitting right after a character the player never bothered to name — is exactly the kind of place you'd stash a covert message: it looks like normal "clutter" data to anyone skimming the file, but it's actually a binary payload.

## Step 5 — Decoding the Message

Treating `0x03` as bit `1` and `0x00` as bit `0` turns the 156-byte block into a 156-bit stream. Grouping it into 8-bit bytes and converting to ASCII decodes cleanly, with no garbage:

```python
seg = data[0x9d20:0x9dbc]                       # the 156-byte anomaly
bits = ''.join('1' if b else '0' for b in seg)  # 0x03 -> '1', 0x00 -> '0'

chars = []
for i in range(0, len(bits) - 7, 8):
    chars.append(chr(int(bits[i:i+8], 2)))

print(''.join(chars))
```

Output:

```
strong_force_in_you
```

with exactly 4 leftover zero-padding bits at the very end — confirming clean byte alignment and that this is the complete, deliberately-placed message (not a coincidental pattern in real game data).

## Step 6 — Flag

Wrapping the decoded phrase in the required flag format:

```
brunner{strong_force_in_you}
```

A fitting little nod to "may the Force be with you," given the challenge's Star Wars setting — and a satisfying payoff for "staring at his character roster" for three weeks: he wasn't playing the game, he was steganographically encoding a message into his own save file, one custom-part toggle at a time.

## Tools Used

- `file`, `strings`, `xxd` / `od`
- Python 3 (`entropy` sweep, custom UTF-16LE string scanner, bit-run detector, bitstream decoder)

## Key Takeaways

- Always check **both** ASCII and UTF-16LE strings — Windows/game binaries frequently use wide-char encoding, and a plain `strings` pass will miss most of the interesting content.
- An entropy sweep is a fast way to rule in/out "it's just encrypted" before spending time on structural analysis.
- Steganography doesn't need encryption or file-format tricks — a legitimate-looking, low-cardinality data structure (like a "which cosmetic parts are equipped" array) is a great place to hide a binary-encoded message, because it blends in with genuine save data.
- When two candidate values keep showing up in an otherwise numeric field (here, only `0x00` and `0x03`), it's always worth treating them as a bitstream and trying an ASCII decode.
