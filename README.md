# pkgfence

Multi-codebase dependency and supply-chain vulnerability scanner, delivered as a Claude Code skill.

Scans local repos, personal GitHub orgs, and remote SSH web servers for known CVEs, malicious packages (via OpenSSF Malicious Packages `MAL-*` lookups), unpinned GitHub Actions, and behavioral red flags. Produces ranked, triaged reports with copy-pasteable remediation and an opt-in fix-recommendation pipeline that never applies changes automatically.

**Status: 🟡 Planning phase complete, implementation not yet started.**

This repository currently contains only the planning artifacts — no code. Phase 1 of the implementation plan will create the skill source under `~/.claude/skills/pkgfence/` (per the design doc §7 folder layout), and this repo will later host the symlinked or copied skill code alongside the `planning/` historical reference.

## Repository layout

```
pkgfence/
├── README.md                           ← you are here
├── .gitignore                          ← state/, .venv/, __pycache__/, etc.
└── planning/                           ← historical planning artifacts (do not edit after commit)
    ├── design.md                       ← design spec (v2.1, critic-approved)
    ├── plan.md                         ← Phase 1 implementation plan (detailed TDD)
    ├── plan-detail-raw.md              ← raw subagent output from detail rewrite (provenance)
    └── research/
        ├── round1-tooling.md           ← tooling landscape research
        ├── round2-implementation.md    ← implementation-grade API details
        └── round3-prior-art.md         ← prior-art mining (17 projects analyzed)
```

## How to read these artifacts

1. **Start with `planning/design.md`** (1,299 lines) — the architecture, modes, safety invariants, and tool stack. Section 1 has the executive summary; §21 has the change log showing what was fixed between v1 and v2 drafts.
2. **Then `planning/plan.md`** (7,113 lines) — Phase 1 as detailed TDD tasks (58 tasks, 303 bite-sized steps) plus Phase 2-5 milestone outlines. Task 1.1 is the first step when implementation starts.
3. **Research rounds** are optional deep-dive reference — each answers a specific question that came up during design:
   - Round 1: "What tools exist? What's best-in-class?"
   - Round 2: "What are the exact API shapes, install commands, and forensic IOCs?"
   - Round 3: "What have other people already built in this space that we can learn from?"

## Current state (pause gate)

Per Ryan's instruction: *"After the plan is made and we're all happy with it, do not execute, pause, commit, review, pause."*

- ✅ First pause cleared (design + plan both reviewed by critic agent, approved by Ryan)
- 🟡 **Commit in progress** (this README is part of the commit)
- 🟡 Review — pending
- 🟡 **Final pause before execution** — pending

When execution begins, it will follow `planning/plan.md` Task 1.1 onwards via either `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans`. Per `ca-rules.md`, NEVER use `isolation: "worktree"` for executor agents — execute on the current branch directly.

## License

MIT. See `planning/design.md` §14 for the reasoning (borrowed from Trail of Bits' convention: permissive license enables third-party audit, which matters because "scanners are now targets" per the TeamPCP lesson).
