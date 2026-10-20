use rustguard::frame::{CanFrame, Direction};
use rustguard::sha256;
use rustguard::someip::{decode_header, validate_header};
use rustguard::uds::{is_mutating_service, service_name, REQUEST_DOWNLOAD};

fn can(id: u32, extended: bool, fd: bool, length: usize) -> CanFrame {
    CanFrame {
        interface: "can0".to_owned(),
        id,
        extended,
        fd,
        data: vec![0; length],
        timestamp_us: 0,
        direction: Direction::Ingress,
    }
}

#[test]
fn classic_can_accepts_eight_bytes() {
    assert!(can(0x100, false, false, 8).validate().is_ok());
}

#[test]
fn classic_can_rejects_nine_bytes() {
    assert_eq!(can(0x100, false, false, 9).validate(), Err("CAN payload too large"));
}

#[test]
fn can_fd_accepts_sixty_four_bytes() {
    assert!(can(0x100, false, true, 64).validate().is_ok());
}

#[test]
fn can_fd_rejects_sixty_five_bytes() {
    assert!(can(0x100, false, true, 65).validate().is_err());
}

#[test]
fn standard_identifier_is_bounded() {
    assert!(can(0x800, false, false, 0).validate().is_err());
}

#[test]
fn extended_identifier_is_supported() {
    assert!(can(0x1fff_ffff, true, false, 0).validate().is_ok());
}

#[test]
fn extended_identifier_is_bounded() {
    assert!(can(0x2000_0000, true, false, 0).validate().is_err());
}

#[test]
fn someip_header_decodes() {
    let bytes = hex("123400010000000a0001000201010000");
    let header = decode_header(&bytes).unwrap();
    assert_eq!(header.service_id, 0x1234);
    assert_eq!(header.method_id, 1);
    assert_eq!(header.client_id, 1);
    assert_eq!(header.session_id, 2);
}

#[test]
fn someip_short_header_rejected() {
    assert!(decode_header(&[0; 15]).is_err());
}

#[test]
fn valid_someip_header_has_no_findings() {
    let header = decode_header(&hex("123400010000000a0001000201010000")).unwrap();
    assert!(validate_header(&header, 2).is_empty());
}

#[test]
fn someip_protocol_version_checked() {
    let mut bytes = hex("123400010000000a0001000201010000");
    bytes[12] = 2;
    assert!(validate_header(&decode_header(&bytes).unwrap(), 2).contains(&"protocol-version"));
}

#[test]
fn someip_length_checked() {
    let header = decode_header(&hex("12340001000000090001000201010000")).unwrap();
    assert!(validate_header(&header, 2).contains(&"length"));
}

#[test]
fn someip_message_type_checked() {
    let mut bytes = hex("123400010000000a0001000201010000");
    bytes[14] = 0x77;
    assert!(validate_header(&decode_header(&bytes).unwrap(), 2).contains(&"message-type"));
}

#[test]
fn uds_mutating_services_identified() {
    assert!(is_mutating_service(REQUEST_DOWNLOAD));
    assert!(!is_mutating_service(0x22));
}

#[test]
fn uds_service_names_are_available() {
    assert_eq!(service_name(0x22), "ReadDataByIdentifier");
    assert_eq!(service_name(0xff), "Unknown");
}

#[test]
fn sha256_matches_known_vector() {
    assert_eq!(
        sha256::hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn sha256_empty_matches_known_vector() {
    assert_eq!(
        sha256::hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

fn hex(value: &str) -> Vec<u8> {
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).unwrap())
        .collect()
}
