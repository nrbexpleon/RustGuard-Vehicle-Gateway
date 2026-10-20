# Threat model

| Threat | Current control | Production work |
|---|---|---|
| Malformed CAN/SOME/IP/UDS | typed parsers, payload/identifier bounds, quarantine | fuzzing and protocol conformance suites |
| Unknown service/frame | default-deny policy | OEM-approved inventories and signed policy |
| Flooding | per-rule/interface rate windows | persistent counters, burst/token buckets and hardware timestamps |
| Diagnostic abuse | role/session/service rules and explicit programming denial | authenticated tester identity and secure gateway integration |
| Replay | timestamped deterministic evidence | freshness counters, SecOC/MAC verification and persistent anti-replay state |
| Policy tampering | policy version and audit chain | signed policy bundles, secure boot and HSM verification |
| Audit modification | SHA-256 chain | digital signature, trusted timestamp and immutable storage |
| Memory corruption | safe Rust and no unsafe blocks | dependency review, fuzzing and target qualification |
| Resource exhaustion | rule/trace/payload limits | bounded queues, quotas and watchdogs |

Do not use public fixtures for production keys, policies, captures or vehicle identities.
