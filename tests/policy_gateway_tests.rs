use rustguard::audit::AuditChain;
use rustguard::frame::{CanFrame, Direction, Message, SomeIpMessage, UdsMessage};
use rustguard::gateway::Decision;
use rustguard::rate_limit::RateLimiter;
use rustguard::{Action, Gateway, Policy};

const POLICY: &str = "\
version 1.0
\
default drop
\
can speed allow can0 0x100 0x7ff 8 2
\
can blocked quarantine can0 0x300 0x7ff 8 10
\
someip state allow eth0 0x1234 0x1 32 2
\
uds read allow diag0 0x22 0x1 technician 2
\
uds programming drop diag0 0x34 0x2 * 1
";

fn can_message(id: u32, timestamp_us: u64) -> Message {
    Message::Can(CanFrame {
        interface: "can0".to_owned(),
        id,
        extended: false,
        fd: false,
        data: vec![1, 2],
        timestamp_us,
        direction: Direction::Ingress,
    })
}

#[test]
fn policy_parses_version_and_rules() {
    let policy = Policy::parse(POLICY).unwrap();
    assert_eq!(policy.version, "1.0");
    assert_eq!(policy.rules.len(), 5);
    assert_eq!(policy.default_action, Action::Drop);
}

#[test]
fn policy_requires_version() {
    assert!(Policy::parse("default drop").is_err());
}

#[test]
fn policy_rejects_unknown_statement() {
    assert!(Policy::parse("version 1\nmagic value").is_err());
}

#[test]
fn policy_rejects_unknown_action() {
    assert!(Policy::parse("version 1\ndefault explode").is_err());
}

#[test]
fn known_can_is_allowed() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    assert_eq!(gateway.process(&can_message(0x100, 0)).decision, Decision::Allow);
}

#[test]
fn unknown_can_is_dropped_by_default() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    let result = gateway.process(&can_message(0x777, 0));
    assert_eq!(result.decision, Decision::Drop);
    assert_eq!(result.rule, "default");
}

#[test]
fn blocked_can_is_quarantined() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    assert_eq!(gateway.process(&can_message(0x300, 0)).decision, Decision::Quarantine);
}

#[test]
fn malformed_can_is_quarantined_before_policy() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    let mut message = can_message(0x100, 0);
    if let Message::Can(frame) = &mut message {
        frame.data = vec![0; 9];
    }
    assert_eq!(gateway.process(&message).decision, Decision::Quarantine);
}

#[test]
fn rate_limit_blocks_third_message_in_window() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    assert_eq!(gateway.process(&can_message(0x100, 0)).decision, Decision::Allow);
    assert_eq!(gateway.process(&can_message(0x100, 1)).decision, Decision::Allow);
    assert_eq!(gateway.process(&can_message(0x100, 2)).decision, Decision::RateLimited);
}

#[test]
fn rate_limit_resets_after_one_second() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    gateway.process(&can_message(0x100, 0));
    gateway.process(&can_message(0x100, 1));
    assert_eq!(gateway.process(&can_message(0x100, 1_000_000)).decision, Decision::Allow);
}

#[test]
fn someip_rule_allows_expected_service() {
    let message = Message::SomeIp(SomeIpMessage {
        interface: "eth0".to_owned(), service_id: 0x1234, method_id: 1, client_id: 1,
        session_id: 1, interface_version: 1, message_type: 0, payload: vec![1],
        timestamp_us: 0, direction: Direction::Ingress,
    });
    assert_eq!(Gateway::new(Policy::parse(POLICY).unwrap()).process(&message).decision, Decision::Allow);
}

#[test]
fn invalid_someip_type_is_quarantined() {
    let message = Message::SomeIp(SomeIpMessage {
        interface: "eth0".to_owned(), service_id: 0x1234, method_id: 1, client_id: 1,
        session_id: 1, interface_version: 1, message_type: 0x77, payload: vec![],
        timestamp_us: 0, direction: Direction::Ingress,
    });
    assert_eq!(Gateway::new(Policy::parse(POLICY).unwrap()).process(&message).decision, Decision::Quarantine);
}

#[test]
fn uds_read_is_role_restricted() {
    let read = |role: &str| Message::Uds(UdsMessage {
        interface: "diag0".to_owned(), service_id: 0x22, sub_function: None,
        session: 1, role: role.to_owned(), payload: vec![0xf1, 0x90], timestamp_us: 0,
        direction: Direction::Ingress,
    });
    assert_eq!(Gateway::new(Policy::parse(POLICY).unwrap()).process(&read("technician")).decision, Decision::Allow);
    assert_eq!(Gateway::new(Policy::parse(POLICY).unwrap()).process(&read("guest")).decision, Decision::Drop);
}

#[test]
fn uds_programming_is_denied_explicitly() {
    let message = Message::Uds(UdsMessage {
        interface: "diag0".to_owned(), service_id: 0x34, sub_function: None,
        session: 2, role: "technician".to_owned(), payload: vec![0], timestamp_us: 0,
        direction: Direction::Ingress,
    });
    assert_eq!(Gateway::new(Policy::parse(POLICY).unwrap()).process(&message).decision, Decision::Drop);
}

#[test]
fn audit_chain_verifies_after_gateway_events() {
    let mut gateway = Gateway::new(Policy::parse(POLICY).unwrap());
    gateway.process(&can_message(0x100, 0));
    gateway.process(&can_message(0x777, 1));
    assert!(gateway.audit().verify());
    assert_eq!(gateway.audit().records().len(), 2);
}

#[test]
fn standalone_audit_chain_links_records() {
    let mut chain = AuditChain::default();
    chain.append(0, "can0", "can", "rule", "allow", "ok");
    chain.append(1, "can0", "can", "rule", "drop", "blocked");
    assert!(chain.verify());
    assert_eq!(chain.records()[1].previous_hash, chain.records()[0].hash);
}

#[test]
fn rate_limiter_tracks_keys() {
    let mut limiter = RateLimiter::default();
    assert!(limiter.allow("x", 0, 1));
    assert_eq!(limiter.tracked_keys(), 1);
}

#[test]
fn zero_rate_denies_everything() {
    assert!(!RateLimiter::default().allow("x", 0, 0));
}
