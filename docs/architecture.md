# Architecture

## Dependency direction

1. **Protocol/domain:** typed CAN, SOME/IP and UDS messages; no operating-system dependency.
2. **Policy:** deterministic matching and explicit default action.
3. **Gateway:** validation, policy, rate-limiting and audit composition.
4. **Replay:** bounded host trace parser and deterministic execution.
5. **Adapters:** future SocketCAN/Ethernet/HSM/HIL implementations depend inward on domain contracts.

No global mutable state or unsafe Rust is permitted. Hardware and operating-system types must not leak into protocol or policy modules.

## Audit chain

Each canonical record includes sequence, timestamp, interface, protocol, rule, decision, detail and previous SHA-256 hash. Recalculation verifies ordering and content integrity. This is tamper evidence, not a digital signature or trusted timestamp.

## Concurrency path

The initial reference processes messages serially for deterministic evidence. A future concurrent adapter must preserve per-interface ordering, bounded queues and deterministic audit sequence assignment.
