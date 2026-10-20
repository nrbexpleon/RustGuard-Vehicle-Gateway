#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SomeIpHeader {
    pub service_id: u16,
    pub method_id: u16,
    pub length: u32,
    pub client_id: u16,
    pub session_id: u16,
    pub protocol_version: u8,
    pub interface_version: u8,
    pub message_type: u8,
    pub return_code: u8,
}

pub fn decode_header(bytes: &[u8]) -> Result<SomeIpHeader, &'static str> {
    if bytes.len() < 16 {
        return Err("SOME/IP header requires 16 bytes");
    }
    Ok(SomeIpHeader {
        service_id: u16::from_be_bytes([bytes[0], bytes[1]]),
        method_id: u16::from_be_bytes([bytes[2], bytes[3]]),
        length: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        client_id: u16::from_be_bytes([bytes[8], bytes[9]]),
        session_id: u16::from_be_bytes([bytes[10], bytes[11]]),
        protocol_version: bytes[12],
        interface_version: bytes[13],
        message_type: bytes[14],
        return_code: bytes[15],
    })
}

#[must_use]
pub fn validate_header(header: &SomeIpHeader, actual_payload_len: usize) -> Vec<&'static str> {
    let mut findings = Vec::new();
    if header.protocol_version != 1 {
        findings.push("protocol-version");
    }
    if header.length < 8 || usize::try_from(header.length - 8).ok() != Some(actual_payload_len) {
        findings.push("length");
    }
    if !matches!(header.message_type, 0x00 | 0x01 | 0x02 | 0x80 | 0x81 | 0x82) {
        findings.push("message-type");
    }
    findings
}
