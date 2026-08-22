# π-crypt 0.57 — BrunnerCTF

**Category:** Crypto
**Difficulty:** Hard
**Points:** 100
**Author:** Bond

## Challenge Description

> In Brunnerne Inc. we are constantly working to improve our product portfolio and reach still new standards - increasing the benefit to and thereby the enjoyment for our customers ⭐⭐⭐⭐⭐
>
> And in line with this philosophy, while only a few of our users found shortcomings in our last season home made pi-recipe 🥧 Brunnerne aims to cater to everyone. - So we are adjusting it with an inclusion of one of master chef Feistel's classical ingredients adjusted into a custom addition to take it to a new level 👩‍🍳 🧑‍🍳
>
> Enjoy this new version announced with a native Danish twist 🇩🇰 😊

**Attachment:** `crypto_pi-crypt-0-57.zip`, containing:
- `bake.py` — the encryption source
- `unbaked_pi.txt` — 1000 digits of π used as a keystream source
- `baked_pie.txt` — the ciphertext (the encrypted flag)

## TL;DR

The challenge chains two custom ciphers, both keyed with the same secret 64-character key:

1. **`pie_crypt`** — a Vigenère-style stream cipher whose per-character shift is derived from two digits of π, at a position that the key walks through.
2. **`custom_ingredient`** — a 16-round "Feistel network" that mixes four 64-character registers together, again using the same key.

The Feistel layer's `custom_xor` is not real XOR — it's addition mod 100. That makes the entire 16-round network **linear**, with each of the 64 character positions ("lanes") evolving completely independently of the others. Because the ciphertext directly exposes two of the four final registers, and those registers are simple linear multiples of the key digit for that lane, the *entire key* can be recovered algebraically in one shot — no brute force required. Once the key is known, the challenge's own decrypt routine reverses everything and prints the flag.

```
brunner{NB!:_Re-using_the_same_key_without_salting-and-hashing_risks_security_of_all_use-instances,_if_one_instance_leaks_info!}
```

## Step 1 — Reading the Source

`bake.py` defines the 100-character alphabet used throughout the cipher:

```python
base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789æøåÆØÅ .,!?-:()[]/{}=<>+_@^|~%$#&*`'";
```

and asserts a few useful constraints:

```python
assert len(key) == 64
assert all(c in base for c in flag + key) and flag[:8] + flag[-1] == "brunner{}"
assert len(base) == 100 and len(pie) == 1000
```

So we know: the key is exactly 64 characters (a "sentence" per the source comment, spaces replaced with underscores), the flag has the standard `brunner{...}` format, and π is used as a 1000-digit lookup table.

### Layer 1 — `pie_crypt`

```python
def pie_crypt(text: str, key: str, decrypt: bool = False) -> str:
    out = ""
    i = sum(base.index(c) for c in key)
    j = 0
    for c in text:
        d1 = int(pie[i % len(pie)])
        i += base.index(key[j % len(key)])
        j += 1
        d2 = int(pie[i % len(pie)])
        i += base.index(key[j % len(key)])
        j += 1
        shift = 10 * d1 + d2
        out += base[(base.index(c) + (-shift if decrypt else shift)) % len(base)]
    return out
```

For every plaintext character, two digits of π are pulled from a position `i` that walks forward through `unbaked_pi.txt`, driven entirely by the key. Those two digits form a two-digit shift (0–99) applied to the character mod 100 — essentially a keyed, π-derived Vigenère cipher.

### Layer 2 — `custom_ingredient` (the "Feistel network")

```python
def custom_ingredient(text, key, decrypt=False, rounds=16):
    ...
    def custom_xor(s1, s2, decrypt=False):
        return "".join(
            base[(base.index(c1) + base.index(c2) * (-1 if decrypt else 1)) % len(base)]
            for c1, c2 in zip(s1, s2)
        )

    def round_function(previous_left, previous_right, left, right):
        if decrypt:
            ...
        else:
            new_left = previous_right
            new_right = custom_xor(previous_left, custom_xor(previous_right, key))
            return left, right, new_left, new_right

    extra_rounds = rounds - 1
    for _ in range(extra_rounds):
        (previous_left, previous_right, left, right) = round_function(...)
    return "".join(round_function(previous_left, previous_right, left, right))
```

This maintains four 64-character registers — `previous_left`, `previous_right`, `left`, `right` — and rotates them through 16 rounds. Encryption starts with `previous_left = previous_right = "A"*64` (all zeros, since `'A'` is index 0 in `base`), and `left`/`right` set to the two halves of the `pie_crypt` output.

`main()` ties it together:

```python
text = flag
text = pie_crypt(text, key)
text = custom_ingredient(text, key)
```

The final output — written to `baked_pie.txt` — is the *concatenation of all four registers* after 16 rounds, giving a ciphertext exactly **4× the flag's length**.

## Step 2 — Finding the Weak Point

`custom_xor` is named like XOR but is actually **addition mod 100** (subtraction when decrypting). That single choice turns the "Feistel network" into a purely **linear (affine) system** over `Z₁₀₀`. Writing out one round in vector form, per character lane:

```
P' = L
Q' = R
L' = Q
R' = P + Q + K      (K = that lane's key digit, base.index(key[i]))
```

Two important consequences:

- **No cross-lane mixing.** `custom_xor` zips strings position-by-position, so lane `i` (character position `i` in each 64-char register) only ever interacts with lane `i` of the key. All 64 lanes are completely independent sub-problems.
- **No non-linearity.** There's no S-box, no modular multiplication, nothing that breaks linearity. Sixteen rounds of a linear recurrence is still just... linear.

This means the final state after 16 rounds can be written as a fixed linear combination (mod 100) of the initial state and the key digit — and that combination can be computed once, symbolically, for all ciphertexts using this scheme.

## Step 3 — Unrolling the Recurrence Symbolically

Using `sympy`, I set the known initial conditions (`P₀ = Q₀ = 0`, since encryption starts with `"A"*64`) and left `L₀ = a`, `R₀ = b` (the unknown `pie_crypt` output halves) and `K = k` (the unknown key digit for this lane) as symbols, then applied the round function 16 times:

```python
import sympy as sp

a, b, k = sp.symbols('a b k')
P, Q, L, R = sp.Integer(0), sp.Integer(0), a, b
for _ in range(16):
    P, Q, L, R = L, R, Q, P + Q + k

print(sp.expand(P), sp.expand(Q), sp.expand(L), sp.expand(R))
```

Output:

```
P16 = 33*k
Q16 = 54*k
L16 = 13*a + 21*b + 33*k
R16 = 21*a + 34*b + 54*k
```

The key insight: **`P16` and `Q16` don't depend on `a` or `b` at all** — they're pure multiples of the key digit `k`. And since `baked_pie.txt` is literally the concatenation `P16 || Q16 || L16 || R16`, the first two 64-character blocks of the ciphertext directly hand us `P16` and `Q16` for all 64 lanes.

## Step 4 — Recovering the Key

Since `gcd(33, 100) = 1`, `33` is invertible mod 100, so:

```
k = P16 · 33⁻¹  (mod 100)
```

recovers every key digit directly from the ciphertext — no brute force, no guessing. `Q16 = 54·k (mod 100)` serves as a free consistency check.

```python
base = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789æøåÆØÅ .,!?-:()[]/{}=<>+_@^|~%$#&*`'"

with open('baked_pie.txt', encoding='utf-8') as f:
    ct = f.read().strip('\n')

n = len(ct) // 4
P16, Q16 = ct[0:n], ct[n:2*n]

inv33 = pow(33, -1, 100)

key_indices = []
for i in range(n):
    p, q = base.index(P16[i]), base.index(Q16[i])
    k = (p * inv33) % 100
    assert (54 * k) % 100 == q          # sanity check
    key_indices.append(k)

key = "".join(base[idx] for idx in key_indices)
print(key)
```

Result:

```
A_key_can_be_strong_just_by_being_long..._sometimes_at_least_...
```

A very self-aware key: 64 characters "long", but structurally weak because the same key was reused across a fully linear cipher stage.

## Step 5 — Decrypting the Flag

With the key recovered, running the challenge's own `decrypt=True` code paths (`custom_ingredient` then `pie_crypt`, in reverse order) unwraps everything:

```python
with open("baked_pie.txt", encoding="utf-8") as f:
    text = f.read().strip("\n")

t = custom_ingredient(text, key, decrypt=True)
n = len(t) // 4
left, right = t[2*n:3*n], t[3*n:]
flag = pie_crypt(left + right, key, decrypt=True)
print(flag)
```

```
brunner{NB!:_Re-using_the_same_key_without_salting-and-hashing_risks_security_of_all_use-instances,_if_one_instance_leaks_info!}
```

## Takeaways

- **Custom crypto is guilty until proven innocent.** A "Feistel network" is only as strong as its round function — here, `custom_xor` was addition dressed up as XOR, which collapsed 16 rounds into one solvable linear system.
- **Reusing the same key across independent cipher stages is dangerous**, exactly as the flag itself points out: if one stage leaks structural information about the key (as the linear Feistel layer did), it compromises every other stage using that same key — including the otherwise reasonable-looking π-based stream cipher.
- **Look for symbols that let variables cancel out.** Solving 16 rounds by hand would be tedious; letting `sympy` expand the recurrence symbolically turned a "16-round cipher" into two lines of algebra.

## Tools Used

- Python 3
- `sympy` (symbolic linear algebra over the integers, reduced mod 100 by hand)

---

*Flag: `brunner{NB!:_Re-using_the_same_key_without_salting-and-hashing_risks_security_of_all_use-instances,_if_one_instance_leaks_info!}`*
