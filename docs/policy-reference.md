# Policy reference

Statements are whitespace-separated; `#` starts a comment.

- `version <value>` — mandatory policy identity.
- `default <action>` — action when no rule matches.
- `can <name> <action> <interface> <id> <mask> <max_len> <max_hz>`
- `someip <name> <action> <interface> <service> <method> <max_len> <max_hz>`
- `uds <name> <action> <interface> <service> <session> <role> <max_hz>`

Numbers accept decimal or `0x` hexadecimal form. Interface and UDS role may be `*`. Rules use first-match semantics and are limited to 10,000 entries.

Actions:

- `allow`: forward if validation and rate limits pass.
- `drop`: reject and audit.
- `rate-limit`: forward below the configured rate; reject excess.
- `quarantine`: isolate for investigation.
- `audit`: forward while recording an explicit audit decision.

Production policy requires independent review, change control, authenticated deployment and rollback.
