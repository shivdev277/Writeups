# TryHackMe — EndgameTrainer

## Challenge Name
EndgameTrainer

## Category
Web Exploitation

## Difficulty
Easy

## Description
EndgameTrainer is a web-based chess trainer that presents a position which is unambiguously checkmate in one move. However, when you try to play the winning move on the board, the app refuses it and claims it isn't checkmate. The goal of the challenge is to figure out why the app disagrees with the obvious reality of the position, and force the win anyway to retrieve a flag.

The board position given was:
```
FEN: 6k1/5ppp/8/8/8/8/5PPP/R5K1 w - - 0 1
```
Black's king is boxed into the corner on g8 by its own pawns on f7, g7, and h7 — no escape squares. White has a rook on a1 with a fully open a-file. **Ra1–a8** is checkmate: nothing can block or capture the rook, and the king has nowhere to go. Any player, and any real chess engine, would confirm this instantly.

## Tools Used
- Browser DevTools (Network tab, Debugger, Console)
- Browser `fetch()` API (used directly from the console)
- Basic chess knowledge to confirm the mating move

## Methodology
The general approach for this kind of "the app says no, but reality says yes" challenge is:

1. **Don't trust the surface behavior.** If the app blocks something that is clearly correct, the block is happening somewhere inspectable — most likely client-side, since this is a browser app.
2. **Check what code is actually running in the browser.** Open the Network tab and see what JS files are loaded. If game logic is bundled into a script that ships to the client, that logic can be read line-by-line.
3. **Trace the exact function responsible for the "no."** Look for whatever check runs right before a user action is accepted or rejected, and read what it actually does.
4. **Identify the real communication channel to the server.** Most apps eventually make an API call to actually perform the action. Find that call and see what it expects.
5. **Test whether the client-side check and the server-side check are the same thing, or two separate, independently-trustable decisions.** If they're separate, the client one is often just a UX nicety — and can be skipped entirely by calling the server directly.

## Step-by-step Solution

**1. Recon the page's network activity.**
Opening DevTools → Network while loading the app shows two relevant scripts: `app.js` (UI and move handling) and `chess.js` (a full chess rules engine, the well-known `chess.js` library, running entirely client-side).

**2. Read `app.js` to find the move-handling flow.**
The function that fires when you attempt a move is `doMove()`, which calls `preMoveCheck()` before ever contacting the server:
```js
function doMove(from, to) {
  if (!isLegalTarget(from, to)) return false;
  const promotion = needsPromotion(from, to) ? 'q' : undefined;
  if (!preMoveCheck(from, to, promotion)) {
    setElPos(els[from], from, true);
    return true;
  }
  toast(SMUG[Math.floor(Math.random() * SMUG.length)]);
  sendMove(from, to, promotion);
  return true;
}
```

**3. Read `preMoveCheck()` to find the actual logic behind the refusal.**
```js
function preMoveCheck(from, to, promotion) {
  const probe = new Chess(game.fen());
  let result;
  try {
    result = probe.move({ from, to, promotion: promotion || undefined });
  } catch (e) {
    result = null;
  }
  if (result && probe.isCheckmate()) {
    showSystemNotice("I'll shut down your PC if you play that.");
    return false;
  }
  return true;
}
```
This function simulates the move locally, and if the local simulation detects checkmate, it **deliberately blocks the move** and shows a joke warning message. This is the whole trick: the app isn't wrong about chess — it is intentionally sabotaging the winning move using logic that runs entirely in the player's own browser, before the real request is ever sent.

**4. Identify the real endpoint the move would normally go to.**
Further down in `app.js`, the actual move submission happens via `sendMove()`:
```js
async function sendMove(from, to, promotion) {
  const res = await fetch('/api/move', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ from, to, promotion: promotion || undefined })
  });
  ...
}
```
Since `preMoveCheck()` only ever runs inside `doMove()`, and both are just ordinary JavaScript functions executing in the browser, there's nothing stopping a player from calling `/api/move` directly and skipping the client-side gatekeeper entirely.

**5. Submit the mating move directly via the browser console, bypassing the UI.**
This sends the exact same request `sendMove()` would have sent, without ever passing through `preMoveCheck()`.

## Commands Used
```js
fetch('/api/move', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ from: 'a1', to: 'a8' })
}).then(r => r.json()).then(console.log)
```

Server response:
```json
{
  "ok": true,
  "move": "a1a8",
  "fen": "R6k/5ppp/8/8/5P2/8/6PP/6K1 b - - 2 2",
  "status": "checkmate",
  "turn": "b",
  "winner": "white"
}
```

## Lessons Learned
Client-side logic is fine for UX — hints, animations, disabling obviously illegal buttons — but it can never be treated as a trustworthy source of truth for anything security- or game-state-relevant, because any code that ships to a user's browser (or mobile app, or desktop client) can be read, understood, and bypassed by calling the real backend directly. In this case, the "engine" wasn't buggy at all; it was a deliberate client-side gate standing between the player and a legitimate, correct action. The proper fix is to remove that check entirely (or make it purely advisory) and let the server's own independent validation be the only thing that decides whether a move is accepted.

---

### Note on approach and ethics
This writeup covers an always-available TryHackMe practice room, not an active/scored competition, and includes no files the platform restricts from sharing — so documenting the full methodology here is in line with responsible writeup practice. As a general rule for any future writeup in this repo: challenge files that organizers explicitly prohibit sharing don't get published, and outcomes for currently-active competitions (time-boxed CTFs, live scoreboards, etc.) aren't posted until the event has concluded.