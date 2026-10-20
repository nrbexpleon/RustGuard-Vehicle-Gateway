use crate::audit::AuditChain;
use crate::frame::Message;
use crate::policy::{Action, Policy};
use crate::rate_limit::RateLimiter;
use crate::uds;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Decision {
    Allow,
    Drop,
    RateLimited,
    Quarantine,
    Audit,
}

impl Decision {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Drop => "drop",
            Self::RateLimited => "rate-limited",
            Self::Quarantine => "quarantine",
            Self::Audit => "audit",
        }
    }

    #[must_use]
    pub const fn forwards(self) -> bool {
        matches!(self, Self::Allow | Self::Audit)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayOutcome {
    pub decision: Decision,
    pub rule: String,
    pub detail: String,
}

pub struct Gateway {
    policy: Policy,
    limiter: RateLimiter,
    audit: AuditChain,
}

impl Gateway {
    #[must_use]
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            limiter: RateLimiter::default(),
            audit: AuditChain::default(),
        }
    }

    pub fn process(&mut self, message: &Message) -> GatewayOutcome {
        let protocol = protocol_name(message);
        if let Err(detail) = validate_message(message) {
            return self.record(message, protocol, "validation", Decision::Quarantine, detail);
        }
        let matched = self.policy.evaluate(message).map(|rule| {
            (
                rule.name().to_owned(),
                rule.action(),
                rule.max_hz(),
            )
        });
        let (rule_name, action, max_hz) = matched.unwrap_or_else(|| {
            (
                "default".to_owned(),
                self.policy.default_action,
                u32::MAX,
            )
        });
        if max_hz != u32::MAX {
            let key = format!("{rule_name}:{}", message.interface());
            if !self.limiter.allow(&key, message.timestamp_us(), max_hz) {
                return self.record(
                    message,
                    protocol,
                    &rule_name,
                    Decision::RateLimited,
                    "message rate exceeded",
                );
            }
        }
        let decision = match action {
            Action::Allow => Decision::Allow,
            Action::Drop => Decision::Drop,
            Action::RateLimit => Decision::Allow,
            Action::Quarantine => Decision::Quarantine,
            Action::Audit => Decision::Audit,
        };
        let detail = if matches!(message, Message::Uds(value) if uds::is_mutating_service(value.service_id)) {
            "mutating diagnostic request explicitly evaluated"
        } else {
            "policy evaluated"
        };
        self.record(message, protocol, &rule_name, decision, detail)
    }

    fn record(
        &mut self,
        message: &Message,
        protocol: &str,
        rule: &str,
        decision: Decision,
        detail: &str,
    ) -> GatewayOutcome {
        self.audit.append(
            message.timestamp_us(),
            message.interface(),
            protocol,
            rule,
            decision.as_str(),
            detail,
        );
        GatewayOutcome {
            decision,
            rule: rule.to_owned(),
            detail: detail.to_owned(),
        }
    }

    #[must_use]
    pub const fn policy(&self) -> &Policy {
        &self.policy
    }

    #[must_use]
    pub const fn audit(&self) -> &AuditChain {
        &self.audit
    }

    #[must_use]
    pub fn tracked_rate_keys(&self) -> usize {
        self.limiter.tracked_keys()
    }
}

fn validate_message(message: &Message) -> Result<(), &'static str> {
    match message {
        Message::Can(frame) => frame.validate(),
        Message::SomeIp(value) => {
            if value.payload.len() > 1_048_576 {
                Err("SOME/IP payload too large")
            } else if !matches!(value.message_type, 0x00 | 0x01 | 0x02 | 0x80 | 0x81 | 0x82) {
                Err("invalid SOME/IP message type")
            } else {
                Ok(())
            }
        }
        Message::Uds(value) => {
            if value.payload.len() > 4095 {
                Err("UDS payload too large")
            } else if value.role.is_empty() {
                Err("UDS principal role required")
            } else {
                Ok(())
            }
        }
    }
}

const fn protocol_name(message: &Message) -> &'static str {
    match message {
        Message::Can(_) => "can",
        Message::SomeIp(_) => "someip",
        Message::Uds(_) => "uds",
    }
}
