# Skill: tasteskill_integration

## Where the taste skills are
The installer placed them at `.agents/.skills/.agents/skills/<name>/` (nested), with copies for other tools in sibling folders. Reference them by full path. At the start of a frontend session, list every skill you can load and its path, and report any that are not discoverable.

## Before using any taste skill
Read its SKILL.md scope statement. If it excludes dashboards, data tables or multi-step product UI, do not apply it to analyst surfaces.

## Routing
- full-output-enforcement: all surfaces. Read its SKILL.md and confirm it is the completeness discipline (no placeholders, no skipped sections). Run it as part of every pre-flight.
- design-taste-frontend: the optional landing page only. Use the unsuffixed folder and ignore design-taste-frontend-v1 unless its README says otherwise.
- redesign-existing-projects: landing page only, and only if it is being redesigned.
- brandkit, image-to-code, imagegen-frontend-web, imagegen-frontend-mobile, stitch-design-taste, gpt-taste, high-end-visual-design, industrial-brutalist-ui, minimalist-ui: not used unless the team approves for the landing page. Never applied to analyst surfaces.

## Landing page brief
```
Loaded: design-taste-frontend as the only source of design rules for this page.
Page kind: landing (public, government security context)
Product: SecureMailScope, passive cryptographic posture assessment of email
  traffic from PCAP files
Audience: SOC analysts, forensic teams, evaluators
Vibe words: precise, calm, evidence-first, official. Not startup-glossy.
Stack: Next.js and Tailwind, using the existing tokens in tailwind.config.ts
Avoid: gradient glow, glassmorphism, grain, consumer-SaaS look
Step 1: declare the design read in one sentence and the three dial values
with one-line reasoning each. Stop.
```
Review the declared read before it builds anything.
