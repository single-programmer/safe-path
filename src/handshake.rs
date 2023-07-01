#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254,
    Unknown(u8),
}

impl From<u8> for HandshakeType {
    fn from(val: u8) -> Self {
        match val {
            1 => HandshakeType::ClientHello,
            2 => HandshakeType::ServerHello,
            4 => HandshakeType::NewSessionTicket,
            5 => HandshakeType::EndOfEarlyData,
            8 => HandshakeType::EncryptedExtensions,
            11 => HandshakeType::Certificate,
            13 => HandshakeType::CertificateRequest,
            15 => HandshakeType::CertificateVerify,
            20 => HandshakeType::Finished,
            24 => HandshakeType::KeyUpdate,
            254 => HandshakeType::MessageHash,
            _ => HandshakeType::Unknown(val),
        }
    }
}

impl From<HandshakeType> for u8 {
    fn from(val: HandshakeType) -> u8 {
        match val {
            HandshakeType::ClientHello => 1,
            HandshakeType::ServerHello => 2,
            HandshakeType::NewSessionTicket => 4,
            HandshakeType::EndOfEarlyData => 5,
            HandshakeType::EncryptedExtensions => 8,
            HandshakeType::Certificate => 11,
            HandshakeType::CertificateRequest => 13,
            HandshakeType::CertificateVerify => 15,
            HandshakeType::Finished => 20,
            HandshakeType::KeyUpdate => 24,
            HandshakeType::MessageHash => 254,
            HandshakeType::Unknown(val) => val,
        }
    }
}

struct Handshake {
    msg_type: HandshakeType,
    length: u32, // uint24
    body: HandshakeBody,
}

enum HandshakeBody {
    ClientHello(ClientHello),
    ServerHello(ServerHello),
    EndOfEarlyData(EndOfEarlyData),
    EncryptedExtensions(EncryptedExtensions),
    CertificateRequest(CertificateRequest),
    Certificate(Certificate),
    CertificateVerify(CertificateVerify),
    Finished(Finished),
    NewSessionTicket(NewSessionTicket),
    KeyUpdate(KeyUpdate),
    Unknown(Vec<u8>),
}

struct ClientHello {
    legacy_version: u16, // = 0x0303; TLS v1.2
    random: [u8; 32],
    legacy_session_id: Vec<u8>,
    cipher_suites: Vec<u16>,
    legacy_compression_methods: Vec<u8>,
    extensions: Vec<Extension>,
}

const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
const TLS_AES_128_CCM_SHA256: u16 = 0x1304;
const TLS_AES_128_CCM_8_SHA256: u16 = 0x1305;

struct ServerHello {
    legacy_version: u16, // = 0x0303; TLS v1.2
    random: [u8; 32],
    legacy_session_id_echo: Vec<u8>,
    cipher_suite: u16,
    legacy_compression_method: u8, // = 0
    extensions: Vec<Extension>,
}

const HELLO_RETRY_REQUEST: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

struct Extension {
    extension_type: ExtensionType,
    extension_data: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum ExtensionType {
    ServerName = 0,                           /* RFC 6066 */
    MaxFragmentLength = 1,                    /* RFC 6066 */
    StatusRequest = 5,                        /* RFC 6066 */
    SupportedGroups = 10,                     /* RFC 8422, 7919 */
    SignatureAlgorithms = 13,                 /* RFC 8446 */
    UseSrtp = 14,                             /* RFC 5764 */
    Heartbeat = 15,                           /* RFC 6520 */
    ApplicationLayerProtocolNegotiation = 16, /* RFC 7301 */
    SignedCertificateTimestamp = 18,          /* RFC 6962 */
    ClientCertificateType = 19,               /* RFC 7250 */
    ServerCertificateType = 20,               /* RFC 7250 */
    Padding = 21,                             /* RFC 7685 */
    PreSharedKey = 41,                        /* RFC 8446 */
    EarlyData = 42,                           /* RFC 8446 */
    SupportedVersions = 43,                   /* RFC 8446 */
    Cookie = 44,                              /* RFC 8446 */
    PskKeyExchangeModes = 45,                 /* RFC 8446 */
    CertificateAuthorities = 47,              /* RFC 8446 */
    OidFilters = 48,                          /* RFC 8446 */
    PostHandshakeAuth = 49,                   /* RFC 8446 */
    SignatureAlgorithmsCert = 50,             /* RFC 8446 */
    KeyShare = 51,                            /* RFC 8446 */
    Unknown(u16),
}

struct SupportedVersionsClient {
    versions: Vec<u16>,
}

struct SupportedVersionsServer {
    selected_version: u16, // = 0x0304; TLS v1.3
}

struct Cookie {
    cookie: Vec<u8>,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum SignatureScheme {
    /* RSASSA-PKCS1-v1_5 algorithms */
    RsaPkcs1Sha256 = 0x0401,
    RsaPkcs1Sha384 = 0x0501,
    RsaPkcs1Sha512 = 0x0601,

    /* ECDSA algorithms */
    EcdsaSecp256r1Sha256 = 0x0403,
    EcdsaSecp384r1Sha384 = 0x0503,
    EcdsaSecp521r1Sha512 = 0x0603,

    /* RSASSA-PSS algorithms with public key OID rsaEncryption */
    RsaPssRsaeSha256 = 0x0804,
    RsaPssRsaeSha384 = 0x0805,
    RsaPssRsaeSha512 = 0x0806,

    /* EdDSA algorithms */
    Ed25519 = 0x0807,
    Ed448 = 0x0808,

    /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
    RsaPssPssSha256 = 0x0809,
    RsaPssPssSha384 = 0x080a,
    RsaPssPssSha512 = 0x080b,

    /* Legacy algorithms */
    RsaPkcs1Sha1 = 0x0201,
    EcdsaSha1 = 0x0203,

    /* Reserved Code Points */
    PrivateUse(u16), // 0xFE00..=0xFFFF
    Unknown(u16),
}

struct SignatureSchemeList {
    supported_signature_algorithms: Vec<SignatureScheme>,
}

struct CertificateAuthoritiesExtension {
    authorities: Vec<Vec<u8>>,
}

struct OIDFilter {
    certificate_extension_oid: Vec<u8>,
    certificate_extension_values: Vec<u8>,
}

struct OIDFilterExtension {
    filters: Vec<OIDFilter>,
}

struct PostHandshakeAuth {}

#[repr(u16)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum NamedGroup {
    /* Elliptic Curve Groups (ECDHE) */
    Secp256r1 = 0x0017,
    Secp384r1 = 0x0018,
    Secp521r1 = 0x0019,
    X25519 = 0x001d,
    X448 = 0x001e,

    /* Finite Field Groups (DHE) */
    Ffdhe2048 = 0x0100,
    Ffdhe3072 = 0x0101,
    Ffdhe4096 = 0x0102,
    Ffdhe6144 = 0x0103,
    Ffdhe8192 = 0x0104,

    /* Reserved Code Points */
    FfdhePrivateUse(u16), // 0x01FC..=0x01FF,
    EcdhePrivateUse(u16), // 0xFE00..=0xFEFF,
    Unknown(u16),
}
struct NamedGroupList {
    named_group_list: Vec<NamedGroup>,
}

struct KeyShareEntry {
    group: NamedGroup,
    key_exchange: Vec<u8>,
}

struct KeyShareClientHello {
    client_shares: Vec<KeyShareEntry>,
}

struct KeyShareHelloRetryRequest {
    selected_group: NamedGroup,
}

struct KeyShareServerHello {
    server_share: KeyShareEntry,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum PskKeyExchangeMode {
    PskKe = 0,
    PskDheKe = 1,
    Unknown(u8),
}

enum EarlyDataIndication {
    Empty,
    MaxEarlyDataSize(u32),
}

struct PskIdentity {
    identity: Vec<u8>,
    obfuscated_ticket_age: u32,
}

struct OfferedPsks {
    identities: Vec<PskIdentity>,
    binders: Vec<Vec<u8>>,
}

struct PreSharedKeyExtensionClient {
    offered_psks: OfferedPsks
}

struct PreSharedKeyExtensionServer {
    selected_identity: u16,
}

struct EncryptedExtensions {
    extensions: Vec<Extension>,
}

struct CertificateRequest {
    certificate_request_context: Vec<u8>,
    extensions: Vec<Extension>,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum CertificateType {
    X509,
    RawPublicKey,
    Unknown(u8),
}

struct CertificateEntry {
    cert_data: Vec<u8>,
    extensions: Vec<Extension>,
}

struct Certificate {
    certificate_request_context: Vec<u8>,
    certificate_list: Vec<CertificateEntry>,
}

struct CertificateVerify {
    algorithm: SignatureScheme,
    signature: Vec<u8>,
}

struct Finished {
    verify_data: Vec<u8>,
}

struct EndOfEarlyData {}

struct NewSessionTicket {
    ticket_lifetime: u32,
    ticket_age_add: u32,
    ticket_nonce: Vec<u8>,
    ticket: Vec<u8>,
    extensions: Vec<Extension>,
}

#[repr(u8)]
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
enum KeyUpdateRequest {
    UpdateNotRequested = 0,
    UpdateRequested = 1,
    Unknown(u8),
}

struct KeyUpdate {
    request_update: KeyUpdateRequest,
}
