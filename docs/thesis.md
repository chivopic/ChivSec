# Technical thesis (v0.1)

Security analysis of a codebase should be modeled as **invariant-constrained scientific investigation**.

The agent is only more interesting than SAST + LLM review if it can:

1. Extract **testable** security invariants from repository understanding
2. Produce attack-path hypotheses bound to those invariants
3. Reduce each hypothesis to a **minimal executable slice**
4. Confirm or reject with **dynamic evidence**

The brain is invariant + hypothesis + investigation. Sensors (Semgrep, Gitleaks) are optional later. The validator is the judge.
