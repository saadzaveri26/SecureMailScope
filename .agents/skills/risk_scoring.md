# Skill: risk_scoring

## Purpose
Turn findings into an explainable posture score and a prioritized list.

## Posture score
1. Score 0 to 100, higher is better. Start at 100 and subtract weighted penalties. Compute per session, per server endpoint, and per capture.
2. Every penalty is recorded as a factor: name, weight, applied impact, detail, and the finding ids behind it. The UI shows this breakdown, so the score is never a bare number.
3. Weights live in `config/scoring.yaml`, each with a one-line reason. Cap total impact per category so one noisy category cannot hide the rest.
4. Map to a grade (for example A to F) in one place and document the thresholds.

## Context-aware prioritization
Priority rank = severity x exposure x prevalence.
- Exposure: cleartext credentials or a plaintext mailbox session outrank an outdated cipher on an otherwise TLS 1.3 server. Server role inferred from ports and behaviour: inbound relay (25), submission (587/465), mailbox access (143/993/110/995), unknown.
- Prevalence: number of sessions and distinct clients affected.
- Do not present every finding as equally urgent. The top of the list must be explainable in one sentence each.

## Hybrid rule
Deterministic rules set severity. ML output is a separate finding category (anomaly) with its own explanation and never raises or lowers a rule-based severity.

## Rules
- Same input, same score. No randomness in the score.
- null and "not observable" contribute no penalty and no credit, and are listed under limitations.
- Positive practices (TLS 1.3, forward secrecy, implicit TLS, message-level encryption) are shown as positives but cannot offset a critical transport finding.
