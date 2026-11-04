<div align="center">

# 🥋 DOJO

### *every technique class, built for real, struck for real, mirrored for real*

**The range of the HolyShit offensive-security family — 15 buildable vulnerable
replicas (stdlib, lab-bound 127.0.0.1), and every replica SELF-VERIFIES: `bench`
builds it, strikes it with the documented probe, and requires the flaw to
confirm. A replica that doesn't break is a broken replica.**

[![Version](https://img.shields.io/badge/version-2.0.0-blueviolet?style=for-the-badge)](#the-cli)
[![Python](https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](#quickstart)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black)](#quickstart)
[![Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](#why-its-powerful)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![CI](https://github.com/xanstomper/dojo/actions/workflows/verify.yml/badge.svg)](https://github.com/xanstomper/dojo/actions/workflows/verify.yml)
[![Use](https://img.shields.io/badge/use-AUTHORIZED%20TARGETS%20ONLY-crimson)](#the-walls)

**THE FAMILY** — ten mandates, one axis each:

[![00 BARBICAN · the shield](https://img.shields.io/badge/00-BARBICAN%20·%20the%20shield-2E4057?style=for-the-badge)](https://github.com/xanstomper/barbican)
[![01 3AM · the performer](https://img.shields.io/badge/01-3AM%20·%20the%20performer-8B0000?style=for-the-badge)](https://github.com/xanstomper/3am-shinjitsu)
[![02 KAIRO · the synthesizer](https://img.shields.io/badge/02-KAIRO%20·%20the%20synthesizer-6B8E23?style=for-the-badge)](https://github.com/xanstomper/kairo)
[![03 UNDERCROFT · the descent](https://img.shields.io/badge/03-UNDERCROFT%20·%20the%20descent-4B0082?style=for-the-badge)](https://github.com/xanstomper/undercroft)
[![04 HOLYSHIT · the finder](https://img.shields.io/badge/04-HOLYSHIT%20·%20the%20finder-B8860B?style=for-the-badge)](https://github.com/xanstomper/HolyShit)
[![05 SHIKI · the command](https://img.shields.io/badge/05-SHIKI%20·%20the%20command-111111?style=for-the-badge)](https://github.com/xanstomper/shiki)
[![06 KAISHA · the ladder](https://img.shields.io/badge/06-KAISHA%20·%20the%20ladder-704214?style=for-the-badge)](https://github.com/xanstomper/kaisha)
[![07 SHUKAKU · the harvester](https://img.shields.io/badge/07-SHUKAKU%20·%20the%20harvester-8B4513?style=for-the-badge)](https://github.com/xanstomper/shukaku)
[![08 KAGE · the mirror](https://img.shields.io/badge/08-KAGE%20·%20the%20mirror-3A3A3A?style=for-the-badge)](https://github.com/xanstomper/kage)
[![SPYDERMONKEY · dispatcher](https://img.shields.io/badge/SPYDERMONKEY-·%20the%20dispatcher-blueviolet?style=for-the-badge)](https://github.com/xanstomper/spydermonkey)

[How it works](#how-it-works) · [Why it's powerful](#why-its-powerful) ·
[Quickstart](#quickstart) · [The CLI](#the-cli) · [The Walls](#the-walls)

</div>

---

## What is this?

DOJO is where the family trains. Every technique class the family attacks exists
here as a buildable, deliberately vulnerable replica — stdlib `http.server`,
bound to 127.0.0.1, canon-mapped (kairo flaw/seam, shukaku class, CWE), and
self-verifying: the range proves its own replicas are vulnerable before you
touch a real target with the same probe.

## How it works

```
catalog                      15 classes × flaw × seam × canon
    ↓  build --class C       the replica serves on 127.0.0.1:P
    ↓  bench  --class C      build → strike → CONFIRM the flaw (or rc=1)
    ↓  teach --class C       flaw → probe → lesson → the kage rule it should produce
🔥 the range feeds the purple loop, not just the red one
```

Real captured output (every line below is from an actual run):

```
✓ DOJO verify: compile · commands · 15 classes · live build+probe+bench — ALL PASS

  ✓ BOUNDARY   built on http://127.0.0.1:8897 · struck '/api/orders?org_id=foreign' · flaw CONFIRMED
  ✓ MASSASSIGN built on http://127.0.0.1:8891 · struck 'POST /api/user  name=bob&email=bob@lab&role=admin' · flaw CONFIRMED
  ✓ INJECTION  built on http://127.0.0.1:8892 · struck '/search?q={{7*7}}' · flaw CONFIRMED
  ✓ SSRF       built on http://127.0.0.1:8897 · struck '/fetch?url=http://127.0.0.1:9/' · flaw CONFIRMED
  ✓ JWT        built on http://127.0.0.1:8895 · struck '/api/admin?token=eyJhbG...UIn0' · flaw CONFIRMED
  ✓ SESSION    built on http://127.0.0.1:8893 · struck '/session?sid=100' · flaw CONFIRMED
```

## The 15 classes

BOUNDARY (CWE-639) · REPLAY (CWE-294) · HARVEST (CWE-538) · TRAVERSAL (CWE-22) ·
DIRECTORY (CWE-548) · XSS (CWE-79) · REDIRECT (CWE-601) · CRYPTO (CWE-327) ·
NETWORK (CWE-200) · **MASSASSIGN (CWE-915) · INJECTION (CWE-94) · SSRF (CWE-918) ·
JWT (CWE-347) · AUTHN (CWE-287) · SESSION (CWE-384)** — the last six are new in
v2.0. Full table with flaw/seam/canon/probe/lesson: `dojo catalog`, or the
SKILL.md class table.

## Why it's powerful

- **Self-verifying range.** `bench` requires the flaw to confirm — the range
  can never silently rot; `dojo verify` benches a class live on every run.
- **Canon-bound.** Every replica maps to the family's real taxonomy (kairo
  flaws/seams, shukaku classes, CWEs) — training exercises the machine, not
  random CTF trivia.
- **Detection-first lessons.** Every class carries the kage rule it should
  produce — the last step of every lesson is the defender's eyes.
- **CI-safe ranges.** `build --serve-seconds N` makes ranges self-terminating —
  the smoke suite builds a live replica, strikes it, and lets it close itself.
- **Zero dependencies.** Pure Python stdlib; lab-bound to 127.0.0.1 forever.

## Quickstart

```
git clone https://github.com/xanstomper/dojo && cd dojo
python3 scripts/dojo.py catalog
python3 scripts/dojo.py bench --class JWT --port 8801
python3 scripts/dojo.py build --class HARVEST --port 8801   # Ctrl-C to close
```

As a Hermes skill: the installed copy lives at
`~/.hermes/skills/security/dojo/` (the repo is the source of truth).

## The CLI

| Command | What it does |
|---|---|
| `catalog` | every class × flaw × seam × canon |
| `build --class C [--port P] [--serve-seconds N]` | serve a vulnerable replica (127.0.0.1 only; self-terminating with `--serve-seconds`) |
| `bench --class C [--port P]` | build → strike → **CONFIRM the flaw** (the range verifies itself) |
| `teach --class C` | the lesson: flaw → probe → lesson → detection rule |
| `verify` | self-check: compile · commands · 15 classes · live build+probe+bench |

Exit codes: `0` ok · `1` bench/verify failure (flaw not confirmed) · `2` usage.

## The Walls

- **Lab-bound 127.0.0.1 only.** Every replica binds the loopback; nothing else.
- **Documented-PoC classes only.** Replicas demonstrate the family's canon — no
  novel exploitation, no payloads beyond the documented probe.
- **No real data.** Every "secret" in every replica is a fake constant.

## Files

```
dojo/
├── SKILL.md            the doctrine (the class table · walls · lessons)
├── scripts/dojo.py     the range CLI (15 class handlers · bench · self-verify)
├── references/         playbook
├── templates/          state template
├── LICENSE             MIT
└── README.md           this page
```

## Relations

Dispatcher: [`spydermonkey`](https://github.com/xanstomper/spydermonkey) (router ·
fleet · the intelligence layer — its `verify` live gate proof strikes a dojo-style
replica) · Canon: [`kairo`](https://github.com/xanstomper/kairo) ·
[`shukaku`](https://github.com/xanstomper/shukaku) · Purple loop:
[`kage`](https://github.com/xanstomper/kage) · Conductor:
[`shiki`](https://github.com/xanstomper/shiki).

---

<div align="center"><em>strike first here · so the first strike out there counts</em></div>
