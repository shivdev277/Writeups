# TryHackMe Writeup: Operation Slither (OSINT Challenge)

## Challenge Name
Operation Slither

## Category
OSINT (Open Source Intelligence)

## Difficulty
Easy / Beginner-friendly

## Description
A fictional threat actor group known as **Sneaky Viper** has allegedly breached a
telecom company ("TryTelecomMe") and is selling stolen data and attack tooling on
underground forums. The challenge provides forum-post snippets containing usernames
and clues, and tasks the player with using OSINT (Open Source Intelligence)
techniques to:

1. Identify social media accounts tied to a leaked username.
2. Pivot across platforms to uncover linked accounts belonging to other members
   of the group.
3. Extract hidden flags embedded in posts, replies, and file metadata along the
   way.

This is a chained investigation — each task builds on a username or clue
discovered in the previous one, simulating how real-world OSINT investigations
often unfold (one account leads to another, which leads to another platform,
and so on).

## Tools Used
- **Sherlock** — username enumeration across hundreds of social platforms
- **curl** — quick, scriptable HTTP requests to check pages without a full browser
- **Firefox** — manual browsing for platforms requiring authentication or JS
  rendering (e.g., Threads, Instagram)
- **base64** (CLI) — decoding Base64-encoded flag strings
- **exiftool** *(referenced, situational)* — checking image metadata for hidden
  clues
- **Google dorking** (`site:` search operator) — narrowing searches to specific
  platforms/domains

## Methodology

The overall approach followed a consistent, repeatable OSINT loop for each
operator in the group:

1. **Start with a known username** (given in the leaked forum post).
2. **Broad platform sweep** using Sherlock to check where else that username
   is registered.
3. **Triage the results** — many hits from automated tools are false positives
   (dead accounts, unrelated username squats, or generic "unavailable" pages).
   Cross-reference bio text, avatars, and posting style to confirm a genuine
   match before investing time in a lead.
4. **Manually inspect the confirmed platform** — read posts, replies, and bios
   for:
   - Direct mentions of the operation/group
   - Base64-encoded strings (a common way CTF designers hide flags in plain
     sight within text)
   - Links out to *other* platforms (the real pivot point to the next
     operator or clue)
5. **Follow the pivot** to the next platform and repeat the cycle.
6. **Decode any Base64 strings found** to reveal the flag for that stage.

This mirrors real investigative tradecraft: usernames, writing style, and
cross-posted content are often the only threads connecting an anonymous
persona across multiple platforms.

## Step-by-Step Solution

### Task 1 — Identifying the First Operator's Secondary Platform

1. Ran Sherlock against the leaked username:
   ```bash
   sherlock v3n0mbyt3_
   ```
2. Sherlock returned several hits, but most were false positives (an empty
   Discord homepage link, unrelated gaming/coding platforms with coincidental
   username matches, and a geo-blocked Mastodon instance).
3. The platform that actually held relevant content was **Threads**.
4. Logging into Threads (an account is required to view profiles) and
   navigating to the **Replies** tab revealed a reply containing a
   Base64-encoded string.
5. Decoded the string to reveal the first flag.

### Task 2 — Identifying the Second Operator

1. On the same Threads reply thread, the account the first operator was
   replying to revealed the **second operator's handle**.
2. Ran Sherlock against the new handle to check for other platforms.
3. Most results were dead ends again (empty placeholder pages, geo-blocked
   redirects). The real pivot was again through **Threads**, where the second
   operator's **Instagram** link was visible on their profile.
4. On Instagram, a post referenced a **SoundCloud** account and linked to a
   track.
5. On the SoundCloud profile, a *different* track than the one directly linked
   (found by browsing the artist's full track list) contained a Base64 string
   in its **description field**.
6. Decoded the string to reveal the second flag.

### Task 3 — Identifying the Third Operator (in progress)

1. Per the recon guide's hint to check "interactions such as likes, follows,
   collaborations," the next lead was found in the **Followers list** of the
   SoundCloud profile from Task 2.
2. A distinctive, non-generic username stood out among the followers —
   this is the third operator's handle.
3. Given the hint pointing toward "developer or technical platforms" and
   "activity history such as repositories or commits," the next platform to
   check is **GitHub**.
4. The approach going forward:
   - Search for the handle directly on GitHub (`github.com/<handle>`).
   - Review repositories for anything matching the infrastructure described
     in the leaked "for sale" post (Terraform, phishing frameworks, etc.).
   - Check **commit history**, not just the current file state — flags
     hidden in git history (old commit messages, removed files, or diffs)
     are a common CTF technique, since a surface-level look at the repo
     wouldn't reveal them.

## Commands Used

```bash
# Username enumeration
sherlock <username>

# Quick page content check without a full browser
curl -sL "https://example.com/@username"

# Decoding a Base64 flag string
echo '<base64_string>' | base64 -d

# Searching a specific domain via Google dork
firefox "https://www.google.com/search?q=site:github.com+<handle>"

# Cloning a repo to inspect commit history
git clone https://github.com/<handle>/<repo>.git
cd <repo>
git log --all --oneline
```

## Lessons Learned

- **Automated tools give leads, not answers.** Sherlock is great for casting
  a wide net, but the majority of its "hits" on a unique-looking username can
  still be false positives (geo-blocked pages, unrelated accounts, dead
  placeholders). Manual verification is essential before committing time to
  a platform.
- **Authentication walls are common on modern social platforms.** Threads,
  and similarly Instagram, block anonymous scraping — a real account is
  often required to view profile content, which is a realistic constraint
  in genuine OSINT work too.
- **Pivoting is the core skill in OSINT chains.** Each platform rarely
  contains the "final answer" by itself — it contains the *next* clue
  (a linked account, a mentioned platform, a follower list). Reading bios,
  captions, and follower/following lists carefully is often more valuable
  than blindly running more scanning tools.
- **Flags are often hidden in plain sight, encoded.** Base64 is a common,
  simple obfuscation method for CTF flags — recognizing the pattern (a long
  jumbled string of letters/numbers, often padded with `=`) saves time versus
  overthinking where a flag "must" be.
- **Don't stop at the first artifact found.** Commit history, follower
  lists, and secondary posts (not just the first thing you land on) are
  frequently where the *real* next step is hiding — a lesson that applies
  directly to Task 3 of this room.

---
