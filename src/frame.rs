#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Direction {
    Ingress,
    Egress,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanFrame {
    pub interface: String,
    pub id: u32,
    pub extended: bool,
    pub fd: bool,
    pub data: Vec<u8>,
    pub timestamp_us: u64,
    pub direction: Direction,
}

impl CanFrame {
    pub fn validate(&self) -> Result<(), &'static str> {
        let max_id = if self.extended { 0x1fff_ffff } else { 0x7ff };
        if self.id > max_id {
            return Err("CAN identifier out of range");
        }
        let max_len = if self.fd { 64 } else { 8 };
        if self.data.len() > max_len {
            return Err("CAN payload too large");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SomeIpMessage {
    pub interface: String,
    pub service_id: u16,
    pub method_id: u16,
    pub client_id: u16,
    pub session_id: u16,
    pub interface_version: u8,
    pub message_type: u8,
    pub payload: Vec<u8>,
    pub timestamp_us: u64,
    pub direction: Direction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UdsMessage {
    pub interface: String,
    pub service_id: u8,
    pub sub_function: Option<u8>,
    pub session: u8,
    pub role: String,
    pub payload: Vec<u8>,
    pub timestamp_us: u64,
    pub direction: Direction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    Can(CanFrame),
    SomeIp(SomeIpMessage),
    Uds(UdsMessage),
}

impl Message {
    #[must_use]
    pub fn timestamp_us(&self) -> u64 {
        match self {
            Self::Can(value) => value.timestamp_us,
            Self::SomeIp(value) => value.timestamp_us,
            Self::Uds(value) => value.timestamp_us,
        }
    }

    #[must_use]
    pub fn interface(&self) -> &str {
        match self {
            Self::Can(value) => &value.interface,
            Self::SomeIp(value) => &value.interface,
            Self::Uds(value) => &value.interface,
        }
    }

    #[must_use]
    pub fn payload_len(&self) -> usize {
        match self {
            Self::Can(value) => value.data.len(),
            Self::SomeIp(value) => value.payload.len(),
            Self::Uds(value) => value.payload.len(),
        }
    }
}
