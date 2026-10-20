pub const DIAGNOSTIC_SESSION_CONTROL: u8 = 0x10;
pub const SECURITY_ACCESS: u8 = 0x27;
pub const WRITE_DATA_BY_IDENTIFIER: u8 = 0x2e;
pub const ROUTINE_CONTROL: u8 = 0x31;
pub const REQUEST_DOWNLOAD: u8 = 0x34;
pub const TRANSFER_DATA: u8 = 0x36;
pub const ECU_RESET: u8 = 0x11;

#[must_use]
pub const fn is_mutating_service(service_id: u8) -> bool {
    matches!(
        service_id,
        WRITE_DATA_BY_IDENTIFIER | ROUTINE_CONTROL | REQUEST_DOWNLOAD | TRANSFER_DATA | ECU_RESET
    )
}

#[must_use]
pub const fn service_name(service_id: u8) -> &'static str {
    match service_id {
        0x10 => "DiagnosticSessionControl",
        0x11 => "ECUReset",
        0x22 => "ReadDataByIdentifier",
        0x27 => "SecurityAccess",
        0x2e => "WriteDataByIdentifier",
        0x31 => "RoutineControl",
        0x34 => "RequestDownload",
        0x36 => "TransferData",
        0x3e => "TesterPresent",
        _ => "Unknown",
    }
}
