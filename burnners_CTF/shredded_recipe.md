# Shredded Recipe — Crypto (100 pts, Hard)

**Category:** Crypto
**Difficulty:** Hard
**Author:** Vincent
**Flag:** `brunner{i_really_love_solving_equations_with_lattices}`

## Challenge

> Brunnerne Inc. just released their new revolutionary and innovating cake: The *citronkvartmåne* - a new, never before seen cost-saving take on the classic *citronhalvmåne*.
>
> However, they shredded and burned the recipe. We think they may be hiding something with that cake.
>
> I even heard that they might be cutting the citronhalvmåne in half and selling it at a markup. Can you get to the bottom of this and retrieve the recipe?

We're given a zip containing `source.py` and `output.txt`.

## Source

```python
from Crypto.Util.number import getPrime, bytes_to_long
import random

flag = b'brunner{?????????????????????????????????????????????}'
assert len(flag) == 54

p = getPrime(512)
print(p)

x = bytes_to_long(flag[0::3])
y = bytes_to_long(flag[1::3])
z = bytes_to_long(flag[2::3])

a, b, c = (random.randint(2, p) for _ in range(3))
d = (a*x + b*y + c*z) % p
print(a, b, c, d)
```

`output.txt` gives us `p`, `a`, `b`, `c`, `d` — five 512-bit-ish integers.

## Breaking down what's happening

The 54-byte flag is split into three interleaved sub-strings using Python's slice-with-step syntax:

* `x = flag[0::3]` — bytes at positions `0, 3, 6, …, 51` (18 bytes)
* `y = flag[1::3]` — bytes at positions `1, 4, 7, …, 52` (18 bytes)
* `z = flag[2::3]` — bytes at positions `2, 5, 8, …, 53` (18 bytes)

This is the "cutting the citronhalvmåne in half" hint — the flag has literally been "shredded" into three interleaved strips.

Each strip is turned into a big integer (`bytes_to_long`), and the challenge publishes a **single linear equation** tying all three together:

```
a*x + b*y + c*z ≡ d (mod p)
```

`p, a, b, c, d` are all known. `x, y, z` are the three unknowns we need to recover.

## Why this isn't hopeless (the counting argument)

At first glance, one equation with three unknowns looks massively underdetermined — you'd normally need three equations for three unknowns. But `random.randint()` is only called once per variable, no reuse, no oracle — so we can't get more equations. The trick has to lie in the *sizes* of things.

* `p` is a 512-bit prime.
* `x`, `y`, `z` are each **18 bytes = 144 bits**.

$$3 \times 144 = 432 \text{ bits} \ll 512 \text{ bits}$$

There's about 80 bits of "slack" between the space of possible `(x, y, z)` triples and the modulus. That gap is the signature of a **lattice / Closest Vector Problem (CVP)** instance: among all the (astronomically many) triples satisfying the congruence mod `p`, there should be exactly *one* triple where `x`, `y`, `z` are all simultaneously small (144-bit) — and lattice reduction is the standard tool for fishing out that one small solution.

## Squeezing the search space with known plaintext

Before reaching for a lattice, we can shrink the unknowns further using the flag format itself. Every flag is `brunner{...}`, so we know:

* `flag[0:8] = b"brunner{"`
* `flag[53]  = b"}"`

Because `x`, `y`, `z` are interleaved by index mod 3, these known bytes land in predictable places:

| Index | Byte | Stream (`idx % 3`) | Position in stream |
|-------|------|---------------------|---------------------|
| 0 | `b` | x | `x[0]` |
| 1 | `r` | y | `y[0]` |
| 2 | `u` | z | `z[0]` |
| 3 | `n` | x | `x[1]` |
| 4 | `n` | y | `y[1]` |
| 5 | `e` | z | `z[1]` |
| 6 | `r` | x | `x[2]` |
| 7 | `{` | y | `y[2]` |
| 53 | `}` | z | `z[17]` (last byte) |

So we already know the **top 3 bytes of `x`**, the **top 3 bytes of `y`**, and the **top 2 + bottom 1 bytes of `z`**. Writing each integer as a known part plus an unknown remainder:

```
x = X0 * 2^120 + x1        # x1 is 15 unknown bytes (120 bits)
y = Y0 * 2^120 + y1        # y1 is 15 unknown bytes (120 bits)
z = Z0 * 2^128 + z1*2^8 + Z_last   # z1 is 15 unknown bytes (120 bits)
```

Substituting into `a*x + b*y + c*z ≡ d (mod p)` and moving every *known* term to the other side collapses the equation into:

```
A*x1 + B*y1 + C*z1 ≡ D (mod p)
```

where `A, B, C, D` are all values we can compute directly, and `x1, y1, z1` are each bounded by `2^120` — smaller unknowns make the lattice attack more comfortable.

## Setting up the lattice (Kannan embedding)

We want small `x1, y1, z1` satisfying `A*x1 + B*y1 + C*z1 ≡ D (mod p)`. Equivalently, there's some integer `k` with:

```
A*x1 + B*y1 + C*z1 - k*p = D
```

This is a classic setup for **Kannan's embedding technique**, which turns a CVP instance into a Shortest Vector Problem (SVP) instance that LLL can solve directly. Build the following basis matrix (rows generate the lattice):

```
[ 1, 0, 0,  A, 0 ]
[ 0, 1, 0,  B, 0 ]
[ 0, 0, 1,  C, 0 ]
[ 0, 0, 0,  p, 0 ]
[ 0, 0, 0, -D, K ]
```

`K` is an embedding weight, chosen close to the expected size of the unknowns (`2^120`) so the resulting short vector stays balanced across all coordinates.

Taking the integer combination `x1·row1 + y1·row2 + z1·row3 + k·row4 + 1·row5` yields the lattice point:

```
(x1, y1, z1, A*x1 + B*y1 + C*z1 - k*p - D, K) = (x1, y1, z1, 0, K)
```

Since `x1, y1, z1 < 2^120` and `K ≈ 2^120`, this vector has a small norm (~`2^121`) relative to the lattice's determinant (~`p`, i.e. `2^512`) — meaning it's very likely the **shortest vector** in the lattice, and LLL should find it directly without needing brute-force enumeration.

## Solving it

```python
from fpylll import IntegerMatrix, LLL

p, a, b, c, d = ...  # parsed from output.txt

def b2l(bs):
    n = 0
    for byte in bs:
        n = (n << 8) | byte
    return n

X0, Y0, Z0 = b2l(b'bnr'), b2l(b'rn{'), b2l(b'ue')
Z_last = ord('}')

A = a % p
B = b % p
C = (c * (1 << 8)) % p
D = (d - a*X0*(1 << 120) - b*Y0*(1 << 120)
       - c*Z0*(1 << 128) - c*Z_last) % p

K = 1 << 120

M = IntegerMatrix(5, 5)
M[0, 0], M[0, 3] = 1, A
M[1, 1], M[1, 3] = 1, B
M[2, 2], M[2, 3] = 1, C
M[3, 3] = p
M[4, 3], M[4, 4] = -D, K

M = LLL.reduction(M)

# The shortest row is our solution: (x1, y1, z1, 0, K)
x1, y1, z1, _, _ = [M[0, j] for j in range(5)]

x = X0*(1 << 120) + x1
y = Y0*(1 << 120) + y1
z = Z0*(1 << 128) + z1*(1 << 8) + Z_last

xb = x.to_bytes(18, 'big')
yb = y.to_bytes(18, 'big')
zb = z.to_bytes(18, 'big')

flag = bytearray(54)
flag[0::3] = xb
flag[1::3] = yb
flag[2::3] = zb

print(bytes(flag))
```

Running LLL reduction on the 5×5 matrix, the first row of the reduced basis comes out as:

```
(495245216368223157786301809587680357,
 594119905444420360779633628895340915,
 547248283704685955209572079026271331,
 0,
 1329227995784915872903807060280344576)
```

The 4th coordinate is exactly `0` and the 5th matches `K = 2^120` — confirming we've found the intended vector, not a decoy. Splicing `x1, y1, z1` back with the known plaintext bytes and de-interleaving the three streams gives:

```
b'brunner{i_really_love_solving_equations_with_lattices}'
```

## Flag

```
brunner{i_really_love_solving_equations_with_lattices}
```

## Takeaways

* A single linear equation with multiple unknowns isn't automatically unsolvable — check whether the unknowns are *small* relative to the modulus. If `(number of unknowns) × (bit size)` is comfortably less than the modulus's bit size, lattice reduction is worth trying.
* Known plaintext (like a fixed flag prefix/suffix) is free information — use it to shrink the search space before reaching for heavier tools.
* Kannan's embedding is a reliable way to turn an inhomogeneous modular linear equation (CVP-flavored) into a homogeneous shortest-vector problem that plain LLL can solve, without needing exact CVP enumeration.
* This is structurally the same idea behind classic "hidden number problem" attacks (e.g. biased ECDSA nonces) — one equation, bounded unknowns, lattice reduction recovers the secret.
