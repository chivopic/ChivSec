# ChivSec

Autonomous security research agent for codebases. v0.1 is the thesis spike:

**Invariant → hypothesis → investigation → executable slice validation.**

It is not a SAST wrapper and not an LLM summarizer. Semgrep-class tools are not the case opener. A finding is `confirmed` only when a deterministic harness breaks a stated security invariant.

## v0.1 scope

- Language: JavaScript slices (handlers in a small module)
- Families: `authorization` (cross-object / IDOR) and `injection_sink` (shell)
- CLI: `node --experimental-strip-types src/chivsec/cli.ts <fixture>`
- Tests: `node --experimental-strip-types --test src/chivsec/pipeline.test.ts`

## Pass criteria (must stay green)

| Fixture | Expected |
|---|---|
| `tiny-notes` | PUT IDOR **confirmed**; GET and DELETE **rejected** |
| `tiny-notes-fixed` | PUT **rejected** (invariant held) |
| `tiny-shell` | command injection **confirmed** |
| `tiny-shell-safe` | **rejected** |

## Core loop

1. Understand repository (deterministic index)
2. Compile threat model + testable invariants
3. Generate schema-gated hypotheses from invariants
4. Investigate attack paths into a `SecurityHandoff`
5. Run a family validator (slice + fixture + probe + evaluate)
6. Promote findings with a hard rule: no dynamic violation → not confirmed

## Not in v0.1

Accounts, patch generation, generic fuzzing, Python/CodeQL, SAST-first ranking, unbounded agent trees.
