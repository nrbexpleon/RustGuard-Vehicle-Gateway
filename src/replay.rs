use crate::frame::{CanFrame, Direction, Message, SomeIpMessage, UdsMessage};
use crate::gateway::{Decision, Gateway, GatewayOutcome};

#[derive(Clone, Debug)]
pub struct ReplayResult {
    pub outcomes: Vec<GatewayOutcome>,
    pub allowed: usize,
    pub dropped: usize,
    pub rate_limited: usize,
    pub quarantined: usize,
    pub audited: usize,
}

pub fn parse_trace(input: &str) -> Result<Vec<Message>, String> {
    let mut messages = Vec::new();
    for (index, raw) in input.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        let error = |detail: &str| format!("trace line {}: {detail}", index + 1);
        let timestamp_us = fields
            .first()
            .ok_or_else(|| error("timestamp required"))?
            .parse::<u64>()
            .map_err(|_| error("invalid timestamp"))?;
        let message = match fields.get(1).copied() {
            Some("can") if fields.len() == 7 => Message::Can(CanFrame {
                interface: fields[2].to_owned(),
                id: number(fields[3]).map_err(|value| error(&value))?,
                extended: fields[4] == "extended",
                fd: fields[5] == "fd",
                data: hex_bytes(fields[6]).map_err(|value| error(&value))?,
                timestamp_us,
                direction: Direction::Ingress,
            }),
            Some("someip") if fields.len() == 9 => Message::SomeIp(SomeIpMessage {
                interface: fields[2].to_owned(),
                service_id: u16::try_from(number(fields[3]).map_err(|value| error(&value))?)
                    .map_err(|_| error("service id out of range"))?,
                method_id: u16::try_from(number(fields[4]).map_err(|value| error(&value))?)
                    .map_err(|_| error("method id out of range"))?,
                client_id: 1,
                session_id: fields[5].parse().map_err(|_| error("invalid session id"))?,
                interface_version: fields[6]
                    .parse()
                    .map_err(|_| error("invalid interface version"))?,
                message_type: u8::try_from(number(fields[7]).map_err(|value| error(&value))?)
                    .map_err(|_| error("message type out of range"))?,
                payload: hex_bytes(fields[8]).map_err(|value| error(&value))?,
                timestamp_us,
                direction: Direction::Ingress,
            }),
            Some("uds") if fields.len() == 8 => Message::Uds(UdsMessage {
                interface: fields[2].to_owned(),
                service_id: u8::try_from(number(fields[3]).map_err(|value| error(&value))?)
                    .map_err(|_| error("UDS service out of range"))?,
                sub_function: if fields[4] == "-" {
                    None
                } else {
                    Some(
                        u8::try_from(number(fields[4]).map_err(|value| error(&value))?)
                            .map_err(|_| error("sub-function out of range"))?,
                    )
                },
                session: u8::try_from(number(fields[5]).map_err(|value| error(&value))?)
                    .map_err(|_| error("UDS session out of range"))?,
                role: fields[6].to_owned(),
                payload: hex_bytes(fields[7]).map_err(|value| error(&value))?,
                timestamp_us,
                direction: Direction::Ingress,
            }),
            _ => return Err(error("invalid trace statement")),
        };
        messages.push(message);
    }
    if messages.len() > 1_000_000 {
        return Err("trace exceeds 1000000 messages".to_owned());
    }
    messages.sort_by_key(Message::timestamp_us);
    Ok(messages)
}

#[must_use]
pub fn replay(gateway: &mut Gateway, messages: &[Message]) -> ReplayResult {
    let outcomes: Vec<_> = messages.iter().map(|message| gateway.process(message)).collect();
    ReplayResult {
        allowed: count(&outcomes, Decision::Allow),
        dropped: count(&outcomes, Decision::Drop),
        rate_limited: count(&outcomes, Decision::RateLimited),
        quarantined: count(&outcomes, Decision::Quarantine),
        audited: count(&outcomes, Decision::Audit),
        outcomes,
    }
}

fn count(outcomes: &[GatewayOutcome], decision: Decision) -> usize {
    outcomes.iter().filter(|value| value.decision == decision).count()
}

fn number(value: &str) -> Result<u32, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid number: {value}"))
    } else {
        value.parse().map_err(|_| format!("invalid number: {value}"))
    }
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if value == "-" {
        return Ok(Vec::new());
    }
    if value.len() % 2 != 0 || value.len() > 131_072 {
        return Err("invalid hexadecimal payload length".to_owned());
    }
    (0..value.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&value[index..index + 2], 16)
                .map_err(|_| "invalid hexadecimal payload".to_owned())
        })
        .collect()
}
