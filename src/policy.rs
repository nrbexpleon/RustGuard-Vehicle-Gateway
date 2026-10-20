use crate::frame::Message;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Action {
    Allow,
    Drop,
    RateLimit,
    Quarantine,
    Audit,
}

impl Action {
    fn parse(value: &str) -> Result<Self, String> {
        match value {
            "allow" => Ok(Self::Allow),
            "drop" => Ok(Self::Drop),
            "rate-limit" => Ok(Self::RateLimit),
            "quarantine" => Ok(Self::Quarantine),
            "audit" => Ok(Self::Audit),
            _ => Err(format!("unsupported action: {value}")),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Rule {
    Can {
        name: String,
        action: Action,
        interface: String,
        id: u32,
        mask: u32,
        max_len: usize,
        max_hz: u32,
    },
    SomeIp {
        name: String,
        action: Action,
        interface: String,
        service_id: u16,
        method_id: u16,
        max_len: usize,
        max_hz: u32,
    },
    Uds {
        name: String,
        action: Action,
        interface: String,
        service_id: u8,
        session: u8,
        role: String,
        max_hz: u32,
    },
}

impl Rule {
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            Self::Can { name, .. } | Self::SomeIp { name, .. } | Self::Uds { name, .. } => name,
        }
    }

    #[must_use]
    pub fn action(&self) -> Action {
        match self {
            Self::Can { action, .. } | Self::SomeIp { action, .. } | Self::Uds { action, .. } => *action,
        }
    }

    #[must_use]
    pub fn max_hz(&self) -> u32 {
        match self {
            Self::Can { max_hz, .. }
            | Self::SomeIp { max_hz, .. }
            | Self::Uds { max_hz, .. } => *max_hz,
        }
    }

    #[must_use]
    pub fn matches(&self, message: &Message) -> bool {
        match (self, message) {
            (
                Self::Can {
                    interface,
                    id,
                    mask,
                    max_len,
                    ..
                },
                Message::Can(frame),
            ) => {
                wildcard(interface, &frame.interface)
                    && frame.id & mask == id & mask
                    && frame.data.len() <= *max_len
            }
            (
                Self::SomeIp {
                    interface,
                    service_id,
                    method_id,
                    max_len,
                    ..
                },
                Message::SomeIp(value),
            ) => {
                wildcard(interface, &value.interface)
                    && value.service_id == *service_id
                    && value.method_id == *method_id
                    && value.payload.len() <= *max_len
            }
            (
                Self::Uds {
                    interface,
                    service_id,
                    session,
                    role,
                    ..
                },
                Message::Uds(value),
            ) => {
                wildcard(interface, &value.interface)
                    && value.service_id == *service_id
                    && value.session == *session
                    && wildcard(role, &value.role)
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    pub version: String,
    pub default_action: Action,
    pub rules: Vec<Rule>,
}

impl Policy {
    pub fn parse(input: &str) -> Result<Self, String> {
        let mut version = None;
        let mut default_action = Action::Drop;
        let mut rules = Vec::new();
        for (index, raw) in input.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            let fields: Vec<_> = line.split_whitespace().collect();
            let error = |detail: &str| format!("line {}: {detail}", index + 1);
            match fields.first().copied() {
                Some("version") if fields.len() == 2 => version = Some(fields[1].to_owned()),
                Some("default") if fields.len() == 2 => {
                    default_action = Action::parse(fields[1]).map_err(|value| error(&value))?;
                }
                Some("can") if fields.len() == 8 => rules.push(Rule::Can {
                    name: fields[1].to_owned(),
                    action: Action::parse(fields[2]).map_err(|value| error(&value))?,
                    interface: fields[3].to_owned(),
                    id: number(fields[4]).map_err(|value| error(&value))?,
                    mask: number(fields[5]).map_err(|value| error(&value))?,
                    max_len: fields[6].parse().map_err(|_| error("invalid max length"))?,
                    max_hz: fields[7].parse().map_err(|_| error("invalid rate"))?,
                }),
                Some("someip") if fields.len() == 8 => rules.push(Rule::SomeIp {
                    name: fields[1].to_owned(),
                    action: Action::parse(fields[2]).map_err(|value| error(&value))?,
                    interface: fields[3].to_owned(),
                    service_id: u16::try_from(number(fields[4]).map_err(|value| error(&value))?)
                        .map_err(|_| error("service id out of range"))?,
                    method_id: u16::try_from(number(fields[5]).map_err(|value| error(&value))?)
                        .map_err(|_| error("method id out of range"))?,
                    max_len: fields[6].parse().map_err(|_| error("invalid max length"))?,
                    max_hz: fields[7].parse().map_err(|_| error("invalid rate"))?,
                }),
                Some("uds") if fields.len() == 8 => rules.push(Rule::Uds {
                    name: fields[1].to_owned(),
                    action: Action::parse(fields[2]).map_err(|value| error(&value))?,
                    interface: fields[3].to_owned(),
                    service_id: u8::try_from(number(fields[4]).map_err(|value| error(&value))?)
                        .map_err(|_| error("UDS service out of range"))?,
                    session: u8::try_from(number(fields[5]).map_err(|value| error(&value))?)
                        .map_err(|_| error("UDS session out of range"))?,
                    role: fields[6].to_owned(),
                    max_hz: fields[7].parse().map_err(|_| error("invalid rate"))?,
                }),
                _ => return Err(error("invalid policy statement")),
            }
        }
        if rules.len() > 10_000 {
            return Err("policy exceeds 10000 rules".to_owned());
        }
        Ok(Self {
            version: version.ok_or_else(|| "policy version required".to_owned())?,
            default_action,
            rules,
        })
    }

    #[must_use]
    pub fn evaluate(&self, message: &Message) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.matches(message))
    }
}

fn wildcard(expected: &str, actual: &str) -> bool {
    expected == "*" || expected == actual
}

fn number(value: &str) -> Result<u32, String> {
    if let Some(hex) = value.strip_prefix("0x") {
        u32::from_str_radix(hex, 16).map_err(|_| format!("invalid number: {value}"))
    } else {
        value.parse().map_err(|_| format!("invalid number: {value}"))
    }
}
