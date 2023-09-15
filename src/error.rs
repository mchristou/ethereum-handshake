use std::num::TryFromIntError;

use ethereum_types::{H128, H256};
use rlp::DecoderError;
use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Invalid public key {0}")]
    InvalidPublicKey(String),

    #[error("Invalid tag received {0}")]
    InvalidTag(H256),

    #[error("Invalid Mac received {0}")]
    InvalidMac(H128),

    #[error("Invalid input {0}")]
    InvalidInput(String),

    #[error("Auth response did not received")]
    AuthResponse(),

    #[error("Decoder error: {0}")]
    Decoder(#[from] DecoderError),

    #[error("Invalid response received: {0}")]
    InvalidResponse(String),

    #[error("Tcp connection closed")]
    TcpConnectionClosed,

    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),

    #[error("Aes: invalid length")]
    AesInvalidLength(#[from] aes::cipher::InvalidLength),

    #[error("concat_kdf error {0}")]
    ConcatKdf(String),

    #[error("secp256k1 error: {0}")]
    Secp256k1(String),

    #[error("TryFromIntError: {0}")]
    TryFromInt(#[from] TryFromIntError),
}
