use alloy_rlp::Decodable;
use bytes::{Buf, BytesMut};
use log::{debug, error, info};
use tokio_util::codec::{Decoder, Encoder};

use crate::{
    error::{Error, Result},
    handshake::Handshake,
    messages::{Disconnect, Hello, Message, Ping, Pong},
};

enum State {
    Auth,
    AuthAck,
    Frame,
}

pub struct Codec {
    handshake: Handshake,
    state: State,
}

impl Codec {
    pub fn new(handshake: Handshake) -> Self {
        Self {
            handshake,
            state: State::Auth,
        }
    }

    fn handle_incoming_frame(frame: Vec<u8>) -> Result<Message> {
        let (mut message_id, mut message) = frame.split_at(1);
        let message_id: u8 = u8::decode(&mut message_id).unwrap();
        debug!("Message ID received: {}", message_id);

        match message_id {
            0 => {
                let hello = Hello::decode(&mut message)?;
                info!("Hello message from target node:\n{:?}", hello);
                Ok(Message::Hello)
            }
            1 => {
                let disc = Disconnect::decode(&mut message)?;
                info!("Disconnect message from target node:\n{:?}", disc);
                Ok(Message::Disconnect(disc.reason))
            }
            2 => {
                let _ping = Ping::decode(&mut message)?;
                info!("Ping message received");
                Ok(Message::Ping)
            }
            3 => {
                let _pong = Pong::decode(&mut message)?;
                info!("Pong message received");
                Ok(Message::Pong)
            }
            _ => Err(Error::UnsupportedMessageId(message_id)),
        }
    }
}

impl Encoder<Message> for Codec {
    type Error = std::io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        match item {
            Message::Auth => {
                self.state = State::AuthAck;
                let auth = self.handshake.auth();
                dst.extend_from_slice(&auth);
            }
            Message::AuthAck => {
                // Implement AuthAck encoding here
                todo!()
            }
            Message::Hello => {
                let hello = self.handshake.hello_msg();
                dst.extend_from_slice(&hello);
            }
            Message::Disconnect(reason) => {
                let disc = self.handshake.disconnect_msg(reason);
                dst.extend_from_slice(&disc);
            }
            Message::Ping => {
                let ping = self.handshake.ping_msg();
                dst.extend_from_slice(&ping);
            }
            Message::Pong => {
                let pong = self.handshake.pong_msg();
                dst.extend_from_slice(&pong);
            }
            Message::Status(msg) => {
                let status = self.handshake.status_msg(msg);
                dst.extend_from_slice(&status);
            }
        }

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        match self.state {
            State::Auth => {
                self.state = State::AuthAck;
                Ok(None)
            }
            State::AuthAck => {
                if src.len() < 2 {
                    return Ok(None);
                }

                let payload = u16::from_be_bytes([src[0], src[1]]) as usize;
                let total_size = payload + 2;

                if src.len() < total_size {
                    return Ok(None);
                }

                let mut buf = src.split_to(total_size);
                let auth_ack = self.handshake.decrypt(&mut buf)?;
                self.handshake.derive_secrets(auth_ack)?;

                self.state = State::Frame;
                Ok(Some(Message::AuthAck))
            }
            State::Frame => {
                if src.is_empty() {
                    return Ok(None);
                }

                match self.handshake.read_frame(&mut src[..]) {
                    Ok((frame, size_used)) => {
                        src.advance(size_used);
                        Self::handle_incoming_frame(frame).map(Some)
                    }
                    Err(e) => {
                        error!("Failed to read frame: {:?}", e);
                        Ok(None)
                    }
                }
            }
        }
    }
}
