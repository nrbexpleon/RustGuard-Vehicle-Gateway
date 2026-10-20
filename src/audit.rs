use crate::sha256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditRecord {
    pub sequence: u64,
    pub timestamp_us: u64,
    pub interface: String,
    pub protocol: String,
    pub rule: String,
    pub decision: String,
    pub detail: String,
    pub previous_hash: String,
    pub hash: String,
}

#[derive(Default)]
pub struct AuditChain {
    records: Vec<AuditRecord>,
}

impl AuditChain {
    pub fn append(
        &mut self,
        timestamp_us: u64,
        interface: &str,
        protocol: &str,
        rule: &str,
        decision: &str,
        detail: &str,
    ) -> &AuditRecord {
        let sequence = self.records.len() as u64 + 1;
        let previous_hash = self
            .records
            .last()
            .map_or_else(|| "0".repeat(64), |record| record.hash.clone());
        let canonical = format!(
            "{sequence}|{timestamp_us}|{interface}|{protocol}|{rule}|{decision}|{detail}|{previous_hash}"
        );
        let hash = sha256::hex(canonical.as_bytes());
        self.records.push(AuditRecord {
            sequence,
            timestamp_us,
            interface: interface.to_owned(),
            protocol: protocol.to_owned(),
            rule: rule.to_owned(),
            decision: decision.to_owned(),
            detail: detail.to_owned(),
            previous_hash,
            hash,
        });
        self.records.last().expect("record was appended")
    }

    #[must_use]
    pub fn verify(&self) -> bool {
        let mut previous = "0".repeat(64);
        for record in &self.records {
            if record.previous_hash != previous {
                return false;
            }
            let canonical = format!(
                "{}|{}|{}|{}|{}|{}|{}|{}",
                record.sequence,
                record.timestamp_us,
                record.interface,
                record.protocol,
                record.rule,
                record.decision,
                record.detail,
                record.previous_hash
            );
            if sha256::hex(canonical.as_bytes()) != record.hash {
                return false;
            }
            previous.clone_from(&record.hash);
        }
        true
    }

    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }
}
