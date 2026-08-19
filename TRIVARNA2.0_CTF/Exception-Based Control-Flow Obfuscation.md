# Exception-Based Control-Flow Obfuscation — TRIVARNA 2.0 (Reverse Engineering / Android)

**Category:** Reverse Engineering (Android)
**Difficulty:** Medium
**Points:** 150
**Flag format:** `TRIVARNA{...}`

## TL;DR

The challenge ships an Android APK whose flag-checking logic replaces every
`if / else` with a custom `throw` / `catch` exception hierarchy. Decompiling
`classes.dex` and reconstructing the control flow from the exception
handlers shows the "real" branch is reached when the entered seed is **even
and greater than 100**, at which point the app returns the flag as a
hardcoded string constant.

```
TRIVARNA{3xc3p710n_cf6_sm4l1_6r4ph_r3c0ns7ruc710n_6194}
```

---

## 1. Challenge Overview

We're given a single file, `chal08.apk`. The description tells us exactly
what to expect:

> Standard conditional branching (`if` / `else`) in the flag verification
> method has been transformed into `throw` / `catch` exception handlers
> across a custom exception hierarchy (`BranchExceptions`).

So the task is a classic "reverse the check, find the input/output that
produces the flag" — except the `if/else` tree has been rewritten as an
exception-driven state machine, which is a legitimate (if obscure) form of
control-flow obfuscation used to defeat naive decompilers and pattern-based
deobfuscators.

## 2. Tools Used

- `unzip` — extract the APK contents
- [`androguard`](https://github.com/androguard/androguard) — parse
  `classes.dex`, decompile classes, and dump raw Dalvik bytecode
- Manual bytecode reading (Smali-level) to reconstruct the true control flow,
  since the naive decompiler output was incomplete for this method

## 3. Static Analysis

### 3.1 Unpacking the APK

An APK is just a ZIP archive:

```bash
unzip -o chal08.apk -d extracted
```

This yields the usual layout — `AndroidManifest.xml`, `classes.dex`,
`resources.arsc`, etc. The application code lives in `classes.dex`.

### 3.2 Locating the interesting classes

Loading the DEX with androguard and listing class names immediately reveals
the challenge's structure:

```python
from androguard.misc import AnalyzeAPK
a, d, dx = AnalyzeAPK('chal08.apk')

for c in dx.get_classes():
    print(c.name)
```

```
Lcom/ctf/chal08/FlagCheck;
Lcom/ctf/chal08/MainActivity;
Lcom/ctf/chal08/branchexc/BranchBaseExc;
Lcom/ctf/chal08/branchexc/BranchAExc;
Lcom/ctf/chal08/branchexc/BranchBExc;
Lcom/ctf/chal08/branchexc/BranchCExc;
Lcom/ctf/chal08/branchexc/BranchDExc;
Lcom/ctf/chal08/branchexc/BranchEExc;
```

The `branchexc` package with `BranchA/B/C/D/E`-named exception classes is
the obfuscation layer described in the challenge brief — each named
exception effectively stands in for one leg of an `if/else` branch.

### 3.3 Reading `MainActivity`

Before diving into the obfuscated method, it helps to confirm how the input
flows through the app:

```smali
invoke-virtual v0, Landroid/widget/EditText;->getText()Landroid/text/Editable;
invoke-static  v0, Lkotlin/text/StringsKt;->toIntOrNull(Ljava/lang/String;)Ljava/lang/Integer;
...
invoke-virtual v2, v0, Lcom/ctf/chal08/FlagCheck;->checkFlag(I)Ljava/lang/String;
invoke-virtual v1, v0, Landroid/widget/TextView;->setText(Ljava/lang/CharSequence;)V
```

So the UI is trivial: it reads an integer "seed" from a text field, passes
it straight into `FlagCheck.checkFlag(int)`, and displays whatever string
comes back. All the real logic — and the flag itself — lives inside
`checkFlag`.

### 3.4 Decompiling `FlagCheck.checkFlag(int)`

A first-pass decompile (androguard's `get_source()`) gives a *rough*
approximation of the logic, but it truncates the nested try/catch blocks:

```java
public final String checkFlag(int p2) {
    try {
        if ((p2 % 2) != 0) {
            throw new BranchBExc();
        } else {
            throw new BranchAExc();
        }
    } catch (BranchAExc e) {
        if (p2 <= 100) {
            throw new BranchDExc();
        } else {
            throw new BranchCExc();
        }
    } catch (BranchBExc e) {
        String result = "STUSEC{invalid_branch_b}";
    }
    return result; // incomplete — misses the inner catch(C)/catch(D)
}
```

This is enough to see the shape of the obfuscation, but not enough to find
the flag — the decompiler failed to reconstruct the **nested** try/catch
that handles `BranchCExc` and `BranchDExc`. For that we drop to raw Dalvik
bytecode.

### 3.5 Reconstructing the true control flow from bytecode

Dumping every instruction in the method (`method.get_instructions()`)
gives the ground truth:

```smali
rem-int/lit8 v0, v2, 2          ; v0 = seed % 2
if-nez v0, +008h                ; if seed is odd -> jump to "odd" branch

; --- fallthrough: seed is even ---
new-instance v0, BranchAExc
invoke-direct v0, BranchAExc;-><init>()V
throw v0

; --- "odd" branch target ---
new-instance v0, BranchBExc
invoke-direct v0, BranchBExc;-><init>()V
throw v0

; --- catch (BranchBExc) handler ---
const-string v2, "STUSEC{invalid_branch_b}"
goto +16h                       ; -> jumps straight to return

; --- catch (BranchAExc) handler ---
const/16 v0, 100
if-le v2, v0, +008h             ; if seed <= 100 -> jump to "small" branch
new-instance v2, BranchCExc
invoke-direct v2, BranchCExc;-><init>()V
throw v2

; --- "small" branch target ---
new-instance v2, BranchDExc
invoke-direct v2, BranchDExc;-><init>()V
throw v2

; --- catch (BranchDExc) handler ---
const-string v2, "STUSEC{invalid_branch_d}"
goto +3h                        ; -> jumps to return

; --- catch (BranchCExc) handler ---
const-string v2, "STUSEC{3xc3p710n_cf6_sm4l1_6r4ph_r3c0ns7ruc710n_6194}"

; --- shared return ---
return-object v2
```

Translating the exception dance back into plain `if/else`:

```java
public String checkFlag(int seed) {
    if (seed % 2 != 0) {
        return "STUSEC{invalid_branch_b}";     // odd -> dead end
    }
    // seed is even
    if (seed <= 100) {
        return "STUSEC{invalid_branch_d}";     // even, small -> dead end
    }
    // seed is even AND > 100
    return "STUSEC{3xc3p710n_cf6_sm4l1_6r4ph_r3c0ns7ruc710n_6194}";
}
```

The `BranchA/B/C/D` exceptions map one-to-one onto the four leaves of a
two-level `if/else` tree:

| Exception   | Condition                     | Result                     |
|-------------|--------------------------------|-----------------------------|
| `BranchBExc`| `seed` is odd                  | dead-end string              |
| `BranchAExc`| `seed` is even (intermediate)  | → evaluates second condition |
| `BranchDExc`| `seed` even **and** ≤ 100      | dead-end string              |
| `BranchCExc`| `seed` even **and** > 100      | **flag string**              |

`BranchEExc` exists in the class list but is never thrown in `checkFlag` —
a red herring / unused branch, presumably left over from a larger template.

The key insight for defeating this style of obfuscation: **a `throw` inside
a `try` block is just a `goto` to whichever `catch` block matches that
exception type**, and the `catch` blocks themselves can be nested to encode
an arbitrarily deep decision tree. Once you map "which exception is thrown
under which condition" to "which catch block runs," the whole thing
degrades back into ordinary `if/else` logic.

## 4. Getting the Flag Dynamically

Since the payload string is a hardcoded constant (not derived from the
seed value itself), the only thing needed at runtime is to route execution
into the `BranchCExc` branch — i.e. supply **any even integer greater than
100**.

Installing the APK on a device/emulator and entering `102` (or `104`, `500`,
etc.) into the seed field and pressing **Check flag** returns:

```
STUSEC{3xc3p710n_cf6_sm4l1_6r4ph_r3c0ns7ruc710n_6194}
```

> **Note on the prefix:** the string literal embedded in the binary uses
> the `STUSEC{...}` prefix, which is leftover branding from the template
> this challenge was built from. The actual submission format for this
> event is `TRIVARNA{...}`, so the payload just needs to be re-wrapped
> accordingly.

Decoding the leetspeak inside the braces:

```
3xc3p710n        -> exception
cf6              -> cfg
sm4l1            -> small
6r4ph            -> graph
r3c0ns7ruc710n   -> reconstruction
6194             -> (challenge instance id / salt)
```

i.e. **"exception cfg small graph reconstruction"** — a fitting name for a
challenge about rebuilding a control-flow graph (CFG) from exception-based
obfuscation.

## 5. Final Flag

```
TRIVARNA{3xc3p710n_cf6_sm4l1_6r4ph_r3c0ns7ruc710n_6194}
```

## 6. Takeaways

- Exception-based control-flow obfuscation is functionally equivalent to
  regular branching: `throw` = conditional jump, `catch` = branch target.
  Decompilers that don't fully model nested try/catch scopes will produce
  incomplete or misleading pseudocode — always cross-check against raw
  bytecode when the high-level decompile looks suspiciously incomplete
  (e.g. a variable used before an apparent definition, as in the first-pass
  `checkFlag` decompile above).
- Custom exception classes with meaningless names (`BranchAExc`,
  `BranchBExc`, …) are a strong signal of this technique — worth grepping
  for immediately after unpacking an APK.
- Not every class/branch is meaningful — `BranchEExc` was dead code, a
  reminder to verify reachability rather than assuming every artifact
  matters.
- Static analysis alone (no emulator/device needed) was sufficient to fully
  recover the flag, since the "computation" was really just a disguised
  lookup table keyed on two boolean predicates (`even?`, `> 100?`).

---

*Tools: `androguard` (Python), manual Smali/Dalvik bytecode review.*