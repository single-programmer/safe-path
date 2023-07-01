#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ContentType {
    Invalid = 0,
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Unknown(u8)
}

struct TLSPlaintext {
    type_: ContentType,
    legacy_record_version: u16,
    length: u16,
    fragment: Vec<u8>,
}

struct TLSInnerPlaintext {
    content: Vec<u8>,
    type_: ContentType,
    zeros: Vec<u8>,
}

struct TLSCiphertext {
    opaque_type: ContentType,
    legacy_record_version: u16, // = 0x0303 for TLS 1.2
    length: u16,
    encrypted_record: Vec<u8>,
}
