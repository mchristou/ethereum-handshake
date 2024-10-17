use alloy_rlp::{RlpDecodable, RlpEncodable};

pub type Reason = usize;

#[derive(Debug)]
pub enum Message {
    Auth,
    AuthAck,
    Hello,
    Ping,
    Pong,
    Disconnect(Reason),
    Status(Status),
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Hello {
    pub protocol_version: usize,
    pub client_version: String,
    pub capabilities: Vec<Capability>,
    pub port: u16,
    pub id: [u8; 64],
}

impl Hello {
    pub const ID: u8 = 0x00;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Capability {
    pub name: String,
    pub version: usize,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Disconnect {
    pub reason: usize,
}

impl Disconnect {
    pub const ID: u8 = 0x1;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Ping {}

impl Ping {
    pub const ID: u8 = 0x2;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Pong {}

impl Pong {
    pub const ID: u8 = 0x3;
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct ForkId {
    hash: u32,
    next: u64,
}

#[derive(Debug, RlpEncodable, RlpDecodable, PartialEq, Eq)]
pub struct Status {
    pub version: u8,
    pub networkid: u64,
    pub td: u128,
    pub blockhash: [u8; 32],
    pub genesis: [u8; 32],
    pub forkid: ForkId,
}

impl Status {
    pub const ID: u8 = 0x10;
}
