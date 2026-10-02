# Skill: forensics_ui_principles

## Why this exists
The public taste skills are scoped to landing pages, portfolios and redesigns. Their own scope statements exclude dashboards, data tables and multi-step product UI. This skill governs every analyst surface. Lessons carried over from earlier builds are written in.

## Design read (declare before building each surface)
Who uses it: a SOC analyst, forensic examiner or mail administrator. What they are doing: finding what is wrong with email cryptography, proving it, and fixing it. What matters most: the finding and its evidence.

## Direction
- Dense, calm, evidence-first. Think packet-analysis and incident-detail views, not marketing pages.
- Light page shell with real elevation (white surfaces lifting off a tinted background). A dark header bar is fine. Avoid dark-on-dark panels with no contrast between layers.
- Monospace only for technical strings: IPs, ports, fingerprints, cipher suite names, Wireshark filters, config snippets, frame numbers. Headings, labels and body text use one sans-serif family in sentence case.
- Color carries meaning. Fixed severity tokens: critical, high, medium, low, info, plus pass. One brand accent that is not a hue on the severity scale (default action blue #1974B9). Starting values live in tailwind.config.ts and must not be reassigned for decoration.
- Score display: the number, the grade, and the factors behind it visible together.
- Realistic content: cipher suite names like TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, hostnames on example domains, IPs from documentation ranges.

## Reject
Gradient or glow decoration, with one exception: the landing page hero band may use a single 3-stop linear gradient from the hero tokens. No gradient, glow, blurred shape, noise or animation anywhere else. Glassmorphism, grain overlays, scroll-triggered animation, identical bordered card grids for everything, tracked-out all-caps eyebrow labels, terminal or hacker styling for headings, placeholder-shaped data, any hardcoded hex value outside the Tailwind config.

## Pre-flight (any unchecked box blocks shipping)
- [ ] Looks like an analyst tool, not a marketing page.
- [ ] All data is realistic and matches the contract fixtures.
- [ ] Severity uses tokens plus icon plus label.
- [ ] Monospace appears only on technical strings.
- [ ] Not-observable is visibly different from safe.
- [ ] Layers are distinguishable by elevation and contrast.
- [ ] Motion appears only in response to user action.
