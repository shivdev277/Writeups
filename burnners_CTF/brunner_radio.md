# Brunner Radio — Crypto (100 pts)

**Category:** Crypto
**Difficulty:** Medium
**Author:** Bond

## Challenge Description

> To readily be able to share our delicious news with brunsviger-fans even in situations when there is no internet connection available 🚫 we at Brunnerne Inc. are also working on a radio-broadcasting scheme 🚀
>
> ... But I forget: Which frequency were we transmitting on? 📻

**Files provided:** `crypto_brunner-radio.zip`, containing:
- `broadcast.py` — the script that generated the challenge output
- `total_broadcast.txt` — the actual "radio broadcast" data we need to decode

## Initial Recon

Unzipping the archive gives us two files. `broadcast.py` is the source of the challenge, and it's short enough to read in full:

```python
# Brunnerne are ready to broadcast!
# We share the radio-space with others and all messages get mixed up.
# But don't worry, each transmission is broadcast on a different frequency,
# so the signals can be separated at the receiver end
from secret import transmissions

assert len(transmissions) == 9
assert "brunner{" in "".join(transmissions)
bytelen_transmission = 36
assert all(len(t) == bytelen_transmission for t in transmissions)

# As the baking enthusiasts we are, we couldn't help but partially home cook
# our own simplified broadcasting mechanics, transmitting one bit at a time :-)
bits = [[int(b) for c in t for b in f"{ord(c):08b}"] for t in transmissions]

# Each package is retransmitted multiple times before moving on:
bit_repetition_period = 100
bit_length = bytelen_transmission * 8

# Sequential Matrix Of Aggregate Bit-transmissions
smoab = [
    [0 for _ in range(bit_repetition_period)]
    for _ in range(bit_length)
]

for i in range(len(transmissions)):
    wavelength = i + 1
    for j in range(bit_length):
        k = wavelength
        while k <= bit_repetition_period:
            smoab[j][k - 1] += bits[i][j]
            k += wavelength

with open("total_broadcast.txt", "w") as f:
    f.write(
        "\n".join(
            "".join(str(sum_of_bits) for sum_of_bits in aggregated_repeated_bits)
            for aggregated_repeated_bits in smoab
        )
    )
```

So there are **9 secret transmissions**, each exactly **36 bytes** long, and one of them contains the flag (`brunner{...}`). The output file, `total_broadcast.txt`, has **288 lines** (one per bit position, since `36 bytes × 8 bits = 288`), and each line has **100 digit characters**.

## Understanding the "Broadcast" Mechanic

This is the crux of the challenge. Each of the 9 transmissions is assigned a **wavelength** equal to its index + 1 (so transmission `0` → wavelength `1`, transmission `1` → wavelength `2`, ..., transmission `8` → wavelength `9`).

For a given bit position `j` (0 through 287), and a given repetition slot `k` (1 through 100), the value written to the output is:

```
smoab[j][k-1] = Σ bits[i][j]   for every transmission i whose wavelength (i+1) divides k
```

In other words: transmission `i` contributes its bit at position `j` into slot `k` **only when `(i+1)` is a divisor of `k`**. Transmission 1 (wavelength 1) contributes into *every* slot. Transmission 9 (wavelength 9) only contributes into slots 9, 18, 27, .... This is essentially frequency-division multiplexing, dressed up with divisibility instead of literal sine waves — a nice thematic nod to "different frequencies."

Critically, **the bits themselves are never XORed or hidden — they're just summed as small integers**. Since we know exactly *which* transmissions land in *which* slot (that only depends on `k`, not on the secret data), this reduces to a simple **linear algebra problem**.

## Turning It Into a Solvable System

For a fixed bit position `j`, treat the unknowns as a vector `x ∈ {0,1}^9` (the bit at position `j` for each of the 9 transmissions). The 100 values on line `j` of `total_broadcast.txt` are then:

```
b = A · x
```

where `A` is a **fixed 100×9 binary matrix** (it doesn't depend on `j` at all!) defined by:

```
A[k-1][i] = 1   if (i+1) divides k, else 0        (k = 1..100, i = 0..8)
```

This is hugely overdetermined — 100 equations for only 9 unknowns — so it's trivial to solve exactly (and self-verifying) with least squares, rounding the result to the nearest integer, since we know each true unknown is either 0 or 1.

Since `A` is the same for every one of the 288 bit positions, we only need to build it once and reuse it for every line of the file.

## Solution Script

```python
import numpy as np

with open('total_broadcast.txt') as f:
    rows = [line.strip('\r') for line in f.read().split('\n')]

bit_repetition_period = 100
n = 9  # number of transmissions
bit_length = 36 * 8  # 288

# Build the fixed 100x9 divisor matrix
A = np.zeros((bit_repetition_period, n), dtype=int)
for k in range(1, bit_repetition_period + 1):
    for i in range(n):
        if k % (i + 1) == 0:
            A[k - 1][i] = 1

all_bits = np.zeros((n, bit_length), dtype=int)

for j, row in enumerate(rows):
    b = np.array([int(c) for c in row])
    x, *_ = np.linalg.lstsq(A, b, rcond=None)
    xr = np.round(x).astype(int)
    assert np.all(A.dot(xr) == b), f"mismatch at bit {j}"
    all_bits[:, j] = xr

# Repack bits into bytes -> ASCII for each transmission
transmissions = []
for i in range(n):
    bits = all_bits[i]
    chars = [
        chr(int(''.join(map(str, bits[b:b+8])), 2))
        for b in range(0, bit_length, 8)
    ]
    transmissions.append(''.join(chars))

for t in transmissions:
    print(repr(t))
```

## Running It

Executing the script recovers all 9 original transmissions:

```
'hine bright like a diamond. Shine br'
' takes the shot - and it goes in!! T'
'while other can-openers just open th'
'd. But in my opinion the even better'
"'s going to be cloudy, but sunshine "
"cause I'm happyyy. Clap along if you"
'brummer{...brrru-uuuuu-uuum-mmmm...}'
'brunner{Brunsviger_is_in_the_air_<3}'
'othello{Sikke_dog_en_dejlig_kage_:D}'
```

Most of these are decoy song-lyric snippets, and there are two trap "flags" thrown in for good measure:
- `brummer{...}` — a near-miss on the flag *format*, not the real prefix.
- `othello{...}` — a correctly-formatted flag, but for a completely different challenge's prefix.

The genuine flag, matching the `brunner{` prefix asserted in the challenge script, is:

## Flag

```
brunner{Brunsviger_is_in_the_air_<3}
```

## Takeaways

- Always read the challenge source carefully — `broadcast.py` fully described the encoding scheme, so no guessing was required.
- The "multiple frequencies" flavor text was a direct hint toward divisor-based multiplexing rather than literal signal processing.
- Even though the system looked complex at first (100 columns × 288 rows of mixed integer data), recognizing it as **a fixed linear system solved independently per bit position** made recovery straightforward with `numpy.linalg.lstsq`.
- CTF authors love decoys — always double check the flag prefix/format against what the challenge explicitly asserts (`assert "brunner{" in ...`) before submitting.
