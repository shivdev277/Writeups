# U — Residual Silence

**Event:** Trivarna 2.0 — International CTF Championship
**Category:** Digital Forensics
**Difficulty:** Hard
**Points:** 450
**Flag:** `TRIVARNA{dalbir_singh_suhag_arup_raha_sunil_lanba_uri_surgical_strike}`

---

## Challenge Description

> What remains is only a fragment of something once complete. A portion is visible—but it is not enough. The rest has been deliberately scattered, concealed across multiple layers, and mixed with noise. Not every piece is useful. Not every pattern is real.

**Provided files:**

| File | Description |
|---|---|
| `secret.7z` | Password-protected archive |
| `halfkey.txt` | A partially masked template of the archive password |
| `key1.txt` – `key7.txt`, `keys4.txt` | Assorted candidate password fragments, mostly decoys |

---

## TL;DR

The challenge is a two-stage puzzle:

1. Reconstruct the true archive password from a field of near-identical decoy fragments, using a masked template as the filter.
2. Unlock a nested `.7z` → `.rar` archive to reveal seven images, six of which carry loudly self-labeled fake flags. The seventh carries three unlabeled draft strings — the real flag.

---

## Step 1 — Surveying the Files

Extracting the provided archive gives one encrypted `secret.7z` and a handful of `key*.txt` files. Each key file contains a candidate password, sometimes in plaintext, sometimes base64-encoded:

```text
key1.txt   -> 31.278N75.779E@%???#????6*(?$Si   (masked, matches halfkey)
key2.txt   -> 31.278N75.779E@%Gar#Naman6*(^$Si
              31.278N75.779W@%Gur#Saran2*(#$Si
key3.txt   -> 31.278N75.779E@%Gun#Sarun6*(^$Si
key5.txt   -> 31.278N75.779E@%Ga\r\nD0r#Saho6*(&$Si
key6.txt   -> 31.278N75.779E@%Gur#Saran6*(^$Si
key7.txt   -> three variants, each with a structural typo (extra "G" or wrong suffix)
keys4.txt  -> 31.278N75.779E@%Gur#Saran5*(^$Si
```

`halfkey.txt` supplies the ground truth shape of the real password, with unknown segments masked:

```text
31.278N75.779E@%???#????6*(?$Si
```

Breaking this down:

- `???` — a masked **3-character** segment
- `????` — a masked **4-character** segment
- the trailing digit must be `6`
- `?` before `$Si` — a masked **1-character** segment

Every candidate breaks this template in exactly one place — wrong compass direction, wrong digit, an inserted character, or (most commonly) a segment that's the wrong length. Filtering the full candidate pool against the template's exact segment lengths and fixed characters leaves exactly one survivor:

```text
31.278N75.779E@%Gur#Saran6*(^$Si
```

This was confirmed cryptographically, not just by pattern-matching — it actually decrypts the archive:

```bash
$ 7z t -p'31.278N75.779E@%Gur#Saran6*(^$Si' secret.7z
Everything is Ok
```

---

## Step 2 — Peeling the Layers

`secret.7z` contains a single file: `secret.rar`. The same recovered password unlocks it as well:

```bash
$ 7z x -p'31.278N75.779E@%Gur#Saran6*(^$Si' secret.7z
$ unar -p '31.278N75.779E@%Gur#Saran6*(^$Si' secret.rar
```

This produces seven image files, `H1.jpg` through `H7.jpg`. Several are actually WebP images with a `.jpg` extension — the first bit of misdirection.

```bash
$ file H*.jpg
H1.jpg: RIFF (little-endian) data, Web/P image
H2.jpg: JPEG image data, JFIF standard
H3.jpg: JPEG image data, JFIF standard
H4.jpg: JPEG image data, Exif standard
H5.jpg: RIFF (little-endian) data, Web/P image
H6.jpg: RIFF (little-endian) data, Web/P image
H7.jpg: JPEG image data, JFIF standard
```

---

## Step 3 — Finding the Noise

Each JPEG's true image data ends at its EOI marker (`FF D9`); each WebP's true payload ends at the offset given by its RIFF chunk size. In every one of the seven files, extra bytes are appended *after* that point:

```python
# JPEG trailer
eoi = data.rfind(b'\xff\xd9')
trailer = data[eoi+2:]

# WebP trailer
riff_size = struct.unpack('<I', data[4:8])[0]
trailer = data[8 + riff_size:]
```

Decoding these trailers (a mix of plaintext, base64, and hex) surfaces a pile of candidate flags — all wrapped as `UNI6{...}` rather than the event's actual `TRIVARNA{...}` format, and almost all of them **explicitly announce that they are fake**:

| File | Decoded trailer content (abridged) |
|---|---|
| H1 | `TRY_AGAIN_NOT_THIS`, `MULTIPLE_FLAGS_EXIST...KEEP_ANALYZING_FILES_AND_HASHES` |
| H2 | `THIS_IS_NOT_THE_FLAG_BUT_IT_LOOKS_VERY_REAL...` |
| H3 | `John_doe_is_not_the_flag` (hex), `DECOY_FLAG_KEEP_GOING` |
| **H4** | **three drafts, none of which self-identify as fake (see below)** |
| H5 | `FAKE_BUT_LOOKS_REAL_WRONG_PATH_5678` |
| H6 | `John_doe_is_not_the_flag` (same hex as H3), `WRONG_PATH_5678` |
| H7 | `...not_the_flag`, `...fake_layer_detected`, `...fake_transmission` |

Beyond the trailers, a wide net was cast for anything else: EXIF/ICC metadata, RAR/7z archive comments, WebP RIFF sub-chunks, embedded archive signatures, polyglot SOI/RIFF headers, and exhaustive LSB-steganography extraction (all channel-order permutations × all bit-planes × both bit orders, across every image and the original challenge screenshot). `steghide` and `outguess` were also run against the JPEGs with an extensive password list. None of this surfaced anything beyond what's documented above — the images are clean of classic pixel- or metadata-level steganography.

---

## Step 4 — The One File That Doesn't Lie

Re-tallying the decoys file by file exposes an asymmetry: **every file except H4 explicitly labels its embedded strings as fake** ("not_the_flag", "decoy", "wrong_path", "fake_..."). H4 is the only one that doesn't.

H4's three base64-decoded strings are:

```text
1. uni6{dalbir_singh_suhag_arup_raha_sunil_lanba_}                       <- truncated mid-word
2. uni6{dalbir_singh_suhag_arup_raha_sunil_lanba_uri_surgical_strike}    <- complete
3. uni6{dalbir_singh_sunil_lanba_uri_surgical_strike}                    <- names dropped
```

These read as successive drafts rather than independent lies: one cut off, one complete and grammatically consistent, one trimmed. Combined with the complete absence of any "fake" disclaimer anywhere in H4 — unlike the other six files, which all editorialize about being wrong — this identifies string #2 as the genuine content, just wrapped in the wrong prefix (`uni6{}` instead of `TRIVARNA{}`, matching the CTF platform's own branding rather than the event's).

Re-wrapping it in the correct flag format gives the solution:

```text
TRIVARNA{dalbir_singh_suhag_arup_raha_sunil_lanba_uri_surgical_strike}
```

Confirmed correct on submission.

---

## Flag

```text
TRIVARNA{dalbir_singh_suhag_arup_raha_sunil_lanba_uri_surgical_strike}
```

---

## Tools Used

- `7z` / `p7zip-full` — archive inspection and extraction
- `unar` — RAR5 extraction (p7zip's RAR support doesn't cover RAR5 compression)
- `exiftool` — metadata inspection
- `steghide`, `stegseek`, `outguess`, `stegoveritas` — steganography detection/extraction
- `binwalk` — embedded file/signature carving
- Python (`Pillow`, `numpy`) — custom bit-plane and LSB analysis, trailer parsing

## Lessons Learned

- When a puzzle gives you a masked template, use it as a strict filter — segment *lengths*, not just characters, disqualify most decoys instantly.
- Always check for appended data past a file's real end-of-data marker (JPEG EOI, RIFF declared size); it's a common and easy place to stash — or hide — content.
- When a challenge floods you with self-labeled decoys, the absence of a disclaimer is itself a signal. Silence, here, was the tell.