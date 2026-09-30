# Skill: pcap_ingestion

## Purpose
Accept uploaded captures safely and turn them into structured rows. A PCAP is untrusted input and contains other people's private traffic.

## Upload
1. Accept only files whose first bytes are a capture magic number: pcap a1b2c3d4 / d4c3b2a1 (and the nanosecond variants a1b23c4d / 4d3cb2a1), pcapng 0a0d0d0a. The extension is advisory.
2. Enforce a size cap from an environment variable while streaming to disk in chunks. Abort mid-stream when exceeded.
3. Store under a server-generated UUID name inside a fixed directory. The client filename is metadata only, never part of a path. Compute SHA-256 while writing and keep it for the report (chain of custody).
4. Rate-limit uploads per IP.
5. Delete uploaded captures after a configurable retention period (default 24 hours) and on demand.

## Processing
1. Start a background job and return the capture id at once. The client polls status: queued, processing, complete, failed (with a safe error message).
2. tshark is a hard dependency. If it is missing or too old, fail startup with a clear setup error. Do not degrade to a weaker parser silently.
3. Run tshark as a subprocess with an argument list (never shell=True), a timeout, and bounded output. Run the container as a non-root user. Dissectors parse hostile data, so keep the process unprivileged.
4. Prefer streaming field output (`-T fields` with `-e`, or `-T ek`) over one giant `-T json` document for large captures.
5. Use tshark's own TCP reassembly and tcp.stream to group sessions. Do not reimplement reassembly and do not extract stream payloads unless a specific check needs them.
6. Read dissector fields (smtp, imap, pop, tls, x509) instead of following streams wherever possible. That keeps message content out of your process.

## Privacy
- Never persist or log message bodies, attachments, or credentials. SMTP AUTH, IMAP LOGIN and POP3 USER/PASS seen in cleartext become a finding ("credentials sent in cleartext", with frame numbers) and nothing more.
- Logs contain capture ids, counts and rule ids, not payload.

## Rules
- A malformed or truncated capture produces a failed status with a reason, never a stack trace to the client.
- Cleanup temp files in a finally block.
