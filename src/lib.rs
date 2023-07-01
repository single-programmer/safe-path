pub mod handshake;
pub mod record;
pub mod alert;

struct TLSConfiguration {

}

impl TLSConfiguration {
    fn new() -> Self {
        TLSConfiguration {}
    }

    fn open(self) -> TLSSocket {
        todo!()
    }
}

struct TLSSocket{}
