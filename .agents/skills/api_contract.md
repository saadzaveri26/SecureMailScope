# Skill: api_contract

## Purpose
Let frontend and backend be built at the same time by different people without drifting apart.

## Process
1. production_artifacts/API_Contract.md is the single source of truth. Read it before writing any request, response model or fixture.
2. Backend response models (Pydantic) mirror the contract exactly, including enums and nullability.
3. Frontend keeps fixtures in app_build/frontend/fixtures/, one JSON file per endpoint, validated against the same types. A flag NEXT_PUBLIC_USE_FIXTURES=1 serves fixtures instead of calling the API.
4. Fixtures must include the hard cases: a TLS 1.3 session with certificate_observable false, a plaintext session with cleartext auth, a STARTTLS session with downgrade_suspected true, a capture still processing, a failed capture, an empty capture.
5. Changing the contract: edit the file, bump the version, add a Changelog line, tell the other side. Never change a field silently.

## Rules
- Nullable means "not observable" or "not applicable", never "unknown, assume fine".
- Enums are closed. New values need a contract change.
- Use documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and example domains in fixtures.
