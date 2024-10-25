use argh::FromArgs;
use futures::{SinkExt, StreamExt};
use log::{error, info, warn};
use secp256k1::{PublicKey, SecretKey};
use std::{net::IpAddr, process};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

mod codec;
mod ecies;
mod error;
mod handshake;
mod hash_mac;
mod messages;
mod secret;

use crate::{
    codec::Codec,
    error::{Error, Result},
    handshake::Handshake,
    messages::Message,
};

#[derive(FromArgs, Debug)]
/// CLI that performs handshake with Ethereum nodes.
struct Args {
    /// the ID of the target node
    #[argh(positional)]
    id: String,
    /// the IP of the target node
    #[argh(positional)]
    ip: IpAddr,
    /// the port of the target node
    #[argh(positional)]
    port: u16,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var("RUST_LOG", "debug");
    }

    env_logger::init();

    let args: Args = argh::from_env();
    let node_address = format!("{}:{}", args.ip, args.port);
    let id_decoded =
        hex::decode(args.id).map_err(|_| Error::InvalidInput("Invalid node ID".to_string()))?;
    let public_key = public_key_from_slice(&id_decoded)?;

    info!("Connecting to target address: {node_address}");
    match TcpStream::connect(&node_address).await {
        Ok(mut stream) => {
            info!("Connected to target address");
            if let Err(e) = perform_handshake(&mut stream, public_key).await {
                error!("Handshake error: {e}");
            }
        }
        Err(e) => error!("Failed to connect to the given Ethereum node: {e}"),
    }

    Ok(())
}

async fn perform_handshake(stream: &mut TcpStream, node_public_key: PublicKey) -> Result<()> {
    let private_key = SecretKey::new(&mut secp256k1::rand::thread_rng());
    let handshake = Handshake::new(private_key, node_public_key);
    let mut framed = Framed::new(stream, Codec::new(handshake));

    framed.send(Message::Auth).await?;
    info!("Auth message sent to target node");

    while let Some(message) = framed.next().await {
        match message {
            Ok(frame) => match frame {
                Message::Auth => {}
                Message::AuthAck => {
                    framed.send(Message::Hello).await?;
                }
                Message::Hello => {}
                Message::Ping => {
                    framed.send(Message::Pong).await?;
                }
                Message::Pong => {
                    framed.send(Message::Ping).await?;
                }
                Message::Disconnect(_reason) => {
                    process::exit(0);
                }
                Message::Status(msg) => {
                    framed.send(Message::Status(msg)).await?;
                }
            },
            Err(e) => {
                error!("Error receiving message: {e}");
                break;
            }
        }
    }

    warn!("Connection closed by the peer side");

    Ok(())
}

fn public_key_from_slice(data: &[u8]) -> Result<PublicKey> {
    const PUBLIC_KEY_LENGTH: usize = 64;
    const PUBLIC_KEY_WITH_PREFIX_LENGTH: usize = 65;

    if data.len() != PUBLIC_KEY_LENGTH {
        return Err(Error::InvalidInput("Invalid public key length".to_string()));
    }

    let mut s = [4_u8; PUBLIC_KEY_WITH_PREFIX_LENGTH];
    s[1..].copy_from_slice(data);

    PublicKey::from_slice(&s).map_err(|e| Error::InvalidPublicKey(e.to_string()))
}
