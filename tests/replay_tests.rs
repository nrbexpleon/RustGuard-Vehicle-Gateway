use rustguard::replay::{parse_trace, replay};
use rustguard::{Decision, Gateway, Policy};

const POLICY: &str = "version 1\ndefault drop\ncan speed allow can0 0x100 0x7ff 8 1\nsomeip state allow eth0 0x1234 0x1 64 10\nuds read allow diag0 0x22 0x1 technician 10\n";

#[test]
fn trace_parses_all_protocols() {
    let trace = "0 can can0 0x100 standard classic 01\n1 someip eth0 0x1234 0x1 1 1 0x00 02\n2 uds diag0 0x22 - 0x1 technician f190\n";
    assert_eq!(parse_trace(trace).unwrap().len(), 3);
}

#[test]
fn trace_sorts_by_timestamp() {
    let trace = "2 can can0 0x100 standard classic 01\n1 can can0 0x100 standard classic 02\n";
    let parsed = parse_trace(trace).unwrap();
    assert_eq!(parsed[0].timestamp_us(), 1);
}

#[test]
fn trace_ignores_comments_and_blank_lines() {
    let trace = "# comment\n\n0 can can0 0x100 standard classic 01 # speed\n";
    assert_eq!(parse_trace(trace).unwrap().len(), 1);
}

#[test]
fn trace_rejects_bad_protocol() {
    assert!(parse_trace("0 magic data").is_err());
}

#[test]
fn trace_rejects_bad_hex() {
    assert!(parse_trace("0 can can0 0x100 standard classic xyz").is_err());
}

#[test]
fn trace_rejects_odd_hex() {
    assert!(parse_trace("0 can can0 0x100 standard classic abc").is_err());
}

#[test]
fn replay_counts_decisions() {
    let messages = parse_trace(
        "0 can can0 0x100 standard classic 01\n1 can can0 0x777 standard classic 01\n",
    )
    .unwrap();
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    let result = replay(&mut gateway, &messages);
    assert_eq!(result.allowed, 1);
    assert_eq!(result.dropped, 1);
}

#[test]
fn replay_counts_rate_limit() {
    let messages = parse_trace(
        "0 can can0 0x100 standard classic 01\n1 can can0 0x100 standard classic 01\n",
    )
    .unwrap();
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    let result = replay(&mut gateway, &messages);
    assert_eq!(result.rate_limited, 1);
    assert_eq!(result.outcomes[1].decision, Decision::RateLimited);
}

#[test]
fn replay_produces_valid_audit_chain() {
    let messages = parse_trace("0 can can0 0x100 standard classic 01\n").unwrap();
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    replay(&mut gateway, &messages);
    assert!(gateway.audit().verify());
}
