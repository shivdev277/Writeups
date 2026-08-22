# Slis — Crypto (100 pts)

**Category:** Crypto
**Difficulty:** Easy–Medium
**Author:** Bond

## Challenge Description

> Brunnerne likes food 🤩 and:
> Some like it sHOrT 🍿
> So we'll keep it short 🤩
>
> **Attachment:** `crypto_slis.zip`

## Provided Files

The zip contains a single script, `slis.py`:

```python
flag = 'brunner{' + input() + '}'
n = int.from_bytes(flag.encode())
lis = [n//(i+2) - n//(i+3) for i in range(9**5)]
assert sum(lis) == 22263691028918788395010325066307464924652601045336492930678310479674861811846
```

The script takes the secret part of the flag as input, wraps it in `brunner{...}`, converts the resulting bytes to a big integer `n`, builds a list of `9**5 = 59049` terms, and asserts that the sum of that list equals a fixed, given constant. Our job is to recover `n` (and therefore the flag) from that constant.

## Recon

At first glance the list comprehension looks intimidating — 59,049 terms, each involving integer division of a huge number. But the structure of each term is the giveaway:

```python
lis[i] = n // (i + 2) - n // (i + 3)
```

Written out for `i = 0, 1, 2, ..., N-1` (where `N = 9**5 = 59049`), the terms are:

```
(n//2 - n//3) + (n//3 - n//4) + (n//4 - n//5) + ... + (n//(N+1) - n//(N+2))
```

This is a **telescoping sum**: every interior term cancels with its neighbor, leaving only the first and last pieces:

```
sum(lis) = n//2 - n//(N + 2)
```

With `N = 9**5 = 59049`, that's:

```
sum(lis) = n//2 - n//59051
```

So the challenge's 59,049-element assertion collapses into a single, simple equation:

```
n // 2 - n // 59051 == 22263691028918788395010325066307464924652601045336492930678310479674861811846
```

*(This also explains the name — "Slis" is "lis" (the list) with an "S" for "sum", and the flavor text nudges you toward "keeping it short": the intended path is to shrink the problem down to one equation rather than brute-forcing a giant list.)*

## Solving for `n`

Let `f(n) = n//2 - n//59051`. Because both `n//2` and `n//59051` are non-decreasing in `n`, `f(n)` is also non-decreasing — which means we can **binary search** for the value of `n` that produces our target sum.

```python
target = 22263691028918788395010325066307464924652601045336492930678310479674861811846
N = 9**5
R = N + 2  # 59051

def f(n):
    return n // 2 - n // R

# Binary search for the smallest n with f(n) == target
lo, hi = 0, 1 << 400
while f(hi) < target:
    hi <<= 1

while lo < hi:
    mid = (lo + hi) // 2
    if f(mid) < target:
        lo = mid + 1
    else:
        hi = mid

n = lo
print(f(n) == target)  # sanity check
```

This gives us a candidate `n`. But because of the floor divisions, `f` can be flat over a small *plateau* of consecutive integers — several different `n` values can map to the exact same `target`. To be safe, we enumerate the whole plateau and pick the candidate that decodes to valid, printable text:

```python
# Find the full range [start, end] of n satisfying f(n) == target
start = n
end = start
step = 1
probe = start
while f(probe) == target:
    probe += step
    step *= 2
lo2, hi2 = start, probe
while lo2 < hi2:
    mid = (lo2 + hi2 + 1) // 2
    if f(mid) == target:
        lo2 = mid
    else:
        hi2 = mid - 1
end = lo2

for candidate in range(start, end + 1):
    b = candidate.to_bytes((candidate.bit_length() + 7) // 8, 'big')
    try:
        s = b.decode('ascii')
    except UnicodeDecodeError:
        continue
    if s.startswith('brunner{') and s.endswith('}'):
        print(s)
```

In this case the plateau was only **2 integers wide**, and exactly one of them decoded cleanly into an ASCII string wrapped in `brunner{...}`.

## Flag

```
brunner{Pease_porridge_sHOrT_:)}
```

A fitting nod to the nursery rhyme *"Pease porridge hot, pease porridge cold... some like it hot, some like it cold, some like it in the pot, nine days old"* — remixed here as "some like it sHOrT," matching the challenge's food-themed flavor text.

## Takeaways

- **Look for telescoping structure** before writing brute-force code against a huge list/sum — a sum of `f(i) - f(i+1)` terms almost always collapses to `f(first) - f(last)`.
- Once the problem is reduced to a single monotonic equation in `n`, **binary search** is the natural tool to invert integer-division constraints.
- Watch out for **plateaus** created by floor division — always verify a candidate solution decodes to sane, expected output rather than trusting the first integer that satisfies the equation.

---

*Writeup by [your name/handle here]*
