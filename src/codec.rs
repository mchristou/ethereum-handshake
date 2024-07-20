use crate::{
    handshake::Handshake,
    messages::{Disconnect, Hello, Message, Ping, Pong},
};
use bytes::BytesMut;
use tokio_util::codec::{Decoder, Encoder};

use crate::error::Result;

enum State {
    Auth,
    AuthAck,
    Frame,
}
pub struct Codec {
    pub handshake: Handshake,
    state: State,
}

impl Codec {
    pub fn new(handshake: Handshake) -> Self {
        Codec {
            handshake,
            state: State::Auth,
        }
    }

    fn handle_incoming_frame(frame: Vec<u8>) -> Result<Message> {
        let message_id: u8 = rlp::decode(&[frame[0]])?;
        println!("message id {message_id}");

        if message_id == 0 {
            let hello: Hello = rlp::decode(&frame[1..])?;
            println!("Hello message from target node:\n{:?}", hello);
            return Ok(Message::Hello);
        }

        if message_id == 1 {
            let disc: Disconnect = rlp::decode(&frame[1..])?;
            println!("Disconnect message from target node: \n{:?}", disc);
            return Ok(Message::Disconnect(disc.reason));
        }

        if message_id == 2 {
            let _ping: Ping = rlp::decode(&frame[1..])?;
            return Ok(Message::Ping);
        }

        if message_id == 3 {
            let _pong: Pong = rlp::decode(&frame[1..])?;
            return Ok(Message::Pong);
        }

        unimplemented!()
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
                println!("sending ping");
                let ping = self.handshake.ping_msg();
                dst.extend_from_slice(&ping);
            }
            Message::Pong => {
                let pong = self.handshake.pong_msg();
                dst.extend_from_slice(&pong);
            }
        }

        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Message;
    type Error = crate::error::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.state {
                State::Auth => self.state = State::AuthAck,
                State::AuthAck => {
                    if src.len() < 2 {
                        return Ok(None);
                    }

                    let payload = u16::from_be_bytes([src[0], src[1]]) as usize;
                    let total_size = payload + 2;

                    if src.len() < total_size {
                        // incomplete auth ack
                        return Ok(None);
                    }

                    let mut buf = src.split_to(total_size);

                    let auth_ack = self.handshake.decrypt(&mut buf)?;
                    self.handshake.derive_secrets(auth_ack)?;

                    self.state = State::Frame;

                    return Ok(Some(Message::AuthAck));
                }
                State::Frame => {
                    if src.is_empty() {
                        return Ok(None);
                    }

                    if let Ok((frame, size_used)) = self.handshake.read_frame(&mut src[..]) {
                        let _ = src.split_to(size_used);
                        return Ok(Some(Self::handle_incoming_frame(frame)?));
                    }

                    return Ok(None);
                }
            }
        }
    }
}
