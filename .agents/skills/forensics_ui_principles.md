# Skill: forensics_ui_principles

## Why this exists
The public taste skills are scoped to landing pages, portfolios and redesigns. Their own scope statements exclude dashboards, data tables and multi-step product UI. This skill governs every analyst surface. Lessons carried over from earlier builds are written in.

## Design read (declare before building each surface)
Who uses it: a SOC analyst, forensic examiner or mail administrator. What they are doing: finding what is wrong with email cryptography, proving it, and fixing it. What matters most: the finding and its evidence.

## Direction
- Dense, calm, evidence-first. Think packet-analysis and incident-detail views, not marketing pages.
- Light page shell with real elevation (white surfaces lifting off a tinted background). A dark header bar is fine. Avoid dark-on-dark panels with no contrast between layers.
- Monospace only for technical strings: IPs, ports, fingerprints, cipher suite names, Wireshark filters, config snippets, frame numbers. Headings, labels and body text use one sans-serif family in sentence case.
- Color carries meaning. Fixed severity tokens: critical, high, medium, low, info, plus pass. The single brand accent is evidence yellow (#FFD21F), used only for evidence tags, primary buttons on dark bands, key numerals on dark bands and the focus ring. Yellow is never text on a light background. Dark ink bands are allowed for header, hero, stat band and footer. Color is for meaning: severity, state, evidence.
- Score display: the number, the grade, and the factors behind it visible together.
- Realistic content: cipher suite names like TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, hostnames on example domains, IPs from documentation ranges.

## Reject
Gradients, glow, blur shapes and grain are banned with no exception. No glassmorphism, grain overlays, scroll-triggered animation, identical bordered card grids for everything, tracked-out all-caps eyebrow labels, terminal or hacker styling for headings, placeholder-shaped data, any hardcoded hex value outside the Tailwind config.

## Pre-flight (any unchecked box blocks shipping)
- [ ] Looks like an analyst tool, not a marketing page.
- [ ] All data is realistic and matches the contract fixtures.
- [ ] Severity uses tokens plus icon plus label.
- [ ] Monospace appears only on technical strings.
- [ ] Not-observable is visibly different from safe.
- [ ] Layers are distinguishable by elevation and contrast.
- [ ] Motion appears only in response to user action.
