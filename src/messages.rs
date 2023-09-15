use rlp::{Decodable, Encodable};
use secp256k1::PublicKey;

#[derive(Debug)]
pub struct Hello {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: PublicKey,
}

#[derive(Debug)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

#[derive(Debug)]
pub struct Disconnect {
    pub reason: usize,
}

impl Encodable for Disconnect {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(1);
        s.append(&self.reason);
    }
}

impl Decodable for Disconnect {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        Ok(Self {
            reason: rlp.val_at(0)?,
        })
    }
}

impl Encodable for Hello {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(5);
        s.append(&self.protocol_version);
        s.append(&self.client_version);
        s.append_list(&self.capabilities);
        s.append(&self.port);

        let id = &self.id.serialize_uncompressed()[1..65];
        s.append(&id);
    }
}

impl Encodable for Capability {
    fn rlp_append(&self, s: &mut rlp::RlpStream) {
        s.begin_list(2);
        s.append(&self.name);
        s.append(&self.version);
    }
}

impl Decodable for Hello {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let protocol_version: usize = rlp.val_at(0)?;
        let client_version: String = rlp.val_at(1)?;
        let capabilities: Vec<Capability> = rlp.list_at(2)?;
        let port: u16 = rlp.val_at(3)?;
        let id: Vec<u8> = rlp.val_at(4)?;

        let mut s = [0_u8; 65];
        s[0] = 4;
        s[1..].copy_from_slice(&id);
        let id = PublicKey::from_slice(&s).unwrap();

        Ok(Self {
            protocol_version,
            client_version,
            capabilities,
            port,
            id,
        })
    }
}

impl Decodable for Capability {
    fn decode(rlp: &rlp::Rlp) -> Result<Self, rlp::DecoderError> {
        let name: String = rlp.val_at(0)?;
        let ver: usize = rlp.val_at(1)?;

        Ok(Self { name, version: ver })
    }
}
