---
name: dojo
description: "Trigger `dojo`. THE RANGE — the family's training ground: builds vulnerable replicas of every technique class (80 classes, stdlib, lab-bound 127.0.0.1), and every replica SELF-VERIFIES: `dojo bench` builds it, strikes it, and requires the flaw to confirm. Every lesson ends in the detection rule kage should emit."
version: 3.0.0
author: Hermes Agent
license: MIT
platforms: [linux]
metadata:
  hermes:
    tags: [redteam, training, lab, vulnerable-apps, detection, authorized-testing]
    related_skills: [spydermonkey, kairo, kage, shukaku, 3am-shinjitsu, undercroft]
---

# DOJO — The Range Mandate (buildable vulnerable replicas)

The family trains here. DOJO builds deliberately vulnerable replicas of every
technique class the family attacks — stdlib `http.server`, **lab-bound to
127.0.0.1** — so the bench, the engines, and the operator always have something
REAL to strike. No replica leaves the loopback; no lesson is theory.

## What makes this range different

- **Self-verifying replicas.** `dojo bench --class C` builds the replica, strikes
  it with the documented probe, and REQUIRES the flaw to confirm — a replica that
  doesn't break is a broken replica. `dojo verify` benches a class live.
- **The surface tier is generated but real.** Each `ARC-SURF` replica carries
  the archetype's flaw on a different protocol surface — same probe/confirm
  discipline, same bench self-verification (64/64 bench-CONFIRMED).
- **Every class is canon-bound.** Each maps to a kairo flaw/seam or a shukaku
  class and a CWE, so training exercises the family's real taxonomy.
- **Every lesson ends in detection.** Each class carries the kage rule it should
  produce — the range feeds the purple loop, not just the red one.

## The Classes (80 buildable)

16 hand-built archetypes (BOUNDARY … HWDEV) + the v3.0 **surface tier**: every
archetype × 4 delivery surfaces (API / MQTT / DEVICE / CLOUD), all generated,
all bench-verified.

| Class | Flaw · Seam | Canon | Probe → confirm |
|---|---|---|---|
| BOUNDARY | 6 · E | kairo BOUNDARY · CWE-639 | `org_id=foreign` trusted from query |
| REPLAY | 2 · F | kairo REPLAY · CWE-294 | webhook accepted twice, no idempotency |
| HARVEST | 15 · G | shukaku BACKUP · CWE-538 | `/backup.zip` serves the backup |
| TRAVERSAL | 3 · D | kairo type/path · CWE-22 | `../` escapes the web root |
| DIRECTORY | 15 · G | CWE-548 | autoindex lists the secrets |
| XSS | 3 · D | CWE-79 | query reflected unencoded |
| REDIRECT | 7 · A | kairo DOMTAKE · CWE-601 | 302 Location from user input |
| CRYPTO | 10 · J | kairo CRYPTO · CWE-327 | TLSv1.0 + RC4 advertised |
| NETWORK | 14 · N | kairo HDRADIO · CWE-200 | service banners exposed |
| MASSASSIGN | 21 · B | kairo MASS-ASSIGN · CWE-915 | `role=admin` accepted in the POST body |
| INJECTION | 1 · D | CWE-94 | `{{7*7}}` evaluates → 49 |
| SSRF | 12 · N | CWE-918 | server fetches loopback, returns the banner |
| JWT | 6 · C | CWE-347 | alg=none token accepted, signature never checked |
| AUTHN | 8 · C | CWE-287 | empty OTP = "already verified" |
| SESSION | 8 · C | CWE-384 | sequential session ids — sid 100 is admin |
| HWDEV | 6 · E | spydermonkey hardware-canon plane 6 · kairo HWFLASH · CWE-639 | reserved master id `0000` serves the master key |
| `ARC-SURF` (×64) | 3 · S | spydermonkey v6.0 surface tier | each archetype translated to API/MQTT/DEVICE/CLOUD |

## When to Use

- Before an engagement: build the class you're about to attack, prove your probe
  works, THEN touch the real target.
- When the family's engines change: `spydermonkey verify` runs the live gate
  proof; `bench_live.py` scores engines against dojo-style replicas.
- When teaching: `dojo teach --class C` prints flaw → probe → lesson → detection.
- When kage needs proof: a confirmed bench IS the reproduction the rule keys on.

## Walls (non-negotiable)

- **Lab-bound 127.0.0.1 only.** Every replica binds the loopback; nothing else.
- **Documented-PoC classes only.** The replicas demonstrate the family's canon
  classes — no novel exploitation, no payloads beyond the documented probe.
- **No data leaves.** The "secrets" in every replica are fake constants.
- **Self-terminating in CI.** `build --serve-seconds N` — ranges close themselves.

## Tooling

`scripts/dojo.py` — stdlib CLI (exit 0 ok · 1 bench/verify failure · 2 usage):
- `catalog` — every class × flaw × seam × canon
- `build --class C [--port P] [--serve-seconds N]` — serve a replica (127.0.0.1)
- `bench --class C [--port P]` — build → strike → CONFIRM the flaw (self-verifying)
- `teach --class C` — the lesson: flaw → probe → lesson → detection rule
- `verify` — compile · commands · 15 classes · live build+probe+bench

## Files

- `SKILL.md` — this doctrine
- `scripts/dojo.py` — the range CLI (15 class handlers)
- `references/` — playbook
- `templates/` — state template
- `README.md` — the public front page

## Relations

Dispatcher: `spydermonkey` (router · fleet · the intelligence layer) ·
Shield: `barbican` · Canon: `kairo` (flaws/seams) · `shukaku` (classes) ·
Purple loop: `kage` (the detection rule every lesson ends in) ·
Conductor: `shiki`. Family walls apply at every layer.
