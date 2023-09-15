use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::{Bytes, BytesMut};
use ethereum_types::{H128, H256};
use hmac::{Hmac, Mac as h_mac};
use secp256k1::{PublicKey, SecretKey, SECP256K1};
use sha2::{Digest, Sha256};

use crate::{
    error::{Error, Result},
    secret::Aes128Ctr64BE,
};

pub struct Ecies {
    pub private_key: SecretKey,
    pub private_ephemeral_key: SecretKey,
    pub public_key: PublicKey,
    pub remote_public_key: PublicKey,
    pub shared_key: H256,
    pub nonce: H256,
    pub auth: Option<Bytes>,
    pub auth_response: Option<Bytes>,
}

impl Ecies {
    pub fn new(private_key: SecretKey, remote_public_key: PublicKey) -> Self {
        let private_ephemeral_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let public_key = PublicKey::from_secret_key(SECP256K1, &private_key);

        let shared_key = H256::from_slice(
            &secp256k1::ecdh::shared_secret_point(&remote_public_key, &private_key)[..32],
        );

        Ecies {
            private_key,
            private_ephemeral_key,
            public_key,
            remote_public_key,
            shared_key,
            nonce: H256::random(),
            auth: None,
            auth_response: None,
        }
    }

    pub fn decrypt<'a>(
        &mut self,
        data_in: &'a mut [u8],
        read_bytes: &mut u16,
    ) -> Result<&'a mut [u8]> {
        if data_in.len() < 2 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let payload_size = u16::from_be_bytes([data_in[0], data_in[1]]);
        *read_bytes = payload_size + 2;

        self.auth_response = Some(Bytes::copy_from_slice(
            &data_in[..payload_size as usize + 2],
        ));

        if data_in.len() < payload_size as usize + 2 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let (_size, rest) = data_in.split_at_mut(2);

        if rest.len() < 65 {
            return Err(Error::InvalidInput("Input data too short".to_string()));
        }

        let (pub_data, rest) = rest.split_at_mut(65);
        let remote_emphmeral_pub_key =
            PublicKey::from_slice(pub_data).map_err(|e| Error::Secp256k1(e.to_string()))?;

        let (iv, rest) = rest.split_at_mut(16);
        let (encrypted_data, tag) = rest.split_at_mut(payload_size as usize - (65 + 16 + 32));

        let tag = H256::from_slice(&tag[..32]);

        let shared_key = self.calculate_shared_key(&remote_emphmeral_pub_key, &self.private_key)?;

        let (encryption_key, mac_key) = self.derive_keys(&shared_key)?;

        let iv = H128::from_slice(iv);

        let remote_tag =
            Self::calculate_remote_tag(mac_key.as_ref(), iv, encrypted_data, payload_size);

        if tag != remote_tag {
            return Err(Error::InvalidTag(remote_tag));
        }

        let encrypted_key = H128::from_slice(encryption_key.as_bytes());
        let mut decryptor = Aes128Ctr64BE::new(encrypted_key.as_ref().into(), iv.as_ref().into());
        decryptor.apply_keystream(encrypted_data);

        Ok(encrypted_data)
    }

    pub fn encrypt(&self, data_in: BytesMut, data_out: &mut BytesMut) -> Result<usize> {
        let random_secret_key = SecretKey::new(&mut secp256k1::rand::thread_rng());

        let shared_key = self.calculate_shared_key(&self.remote_public_key, &random_secret_key)?;

        let iv = H128::random();

        let (encryption_key, mac_key) = self.derive_keys(&shared_key)?;

        let total_size: u16 = u16::try_from(65 + 16 + data_in.len() + 32).unwrap();

        let encrypted_data = self.encrypt_data(data_in, &iv, &encryption_key);

        let d = self.calculate_tag(&mac_key, &iv, &total_size.to_be_bytes(), &encrypted_data)?;

        self.prepare_output_data(
            data_out,
            &random_secret_key,
            &iv,
            &encrypted_data,
            &d,
            total_size,
        )?;

        Ok(data_out.len())
    }

    fn calculate_remote_tag(
        mac_key: &[u8],
        iv: H128,
        encrypted_data: &mut [u8],
        payload_size: u16,
    ) -> H256 {
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key).expect("HMAC creation failed");
        hmac.update(iv.as_bytes());
        hmac.update(encrypted_data);
        hmac.update(&payload_size.to_be_bytes());

        H256::from_slice(&hmac.finalize().into_bytes())
    }

    fn calculate_tag(
        &self,
        mac_key: &H256,
        iv: &H128,
        total_size: &[u8; 2],
        encrypted_data: &BytesMut,
    ) -> Result<H256> {
        let mut hmac = Hmac::<Sha256>::new_from_slice(mac_key.as_ref())?;
        hmac.update(iv.as_bytes());
        hmac.update(encrypted_data);
        hmac.update(total_size);
        Ok(H256::from_slice(&hmac.finalize().into_bytes()))
    }

    fn calculate_shared_key(
        &self,
        public_key: &PublicKey,
        private_key: &SecretKey,
    ) -> Result<H256> {
        let shared_key_bytes = secp256k1::ecdh::shared_secret_point(public_key, private_key);
        let shared_key = H256::from_slice(&shared_key_bytes[..32]);
        Ok(shared_key)
    }

    fn derive_keys(&self, shared_key: &H256) -> Result<(H128, H256)> {
        let mut key = [0_u8; 32];
        concat_kdf::derive_key_into::<sha2::Sha256>(shared_key.as_bytes(), &[], &mut key)
            .map_err(|e| Error::ConcatKdf(e.to_string()))?;

        let encryption_key = H128::from_slice(&key[..16]);
        let mac_key = H256::from(Sha256::digest(&key[16..32]).as_ref());
        Ok((encryption_key, mac_key))
    }

    fn encrypt_data(&self, data: BytesMut, iv: &H128, encryption_key: &H128) -> BytesMut {
        let mut encryptor = Aes128Ctr64BE::new(encryption_key.as_ref().into(), iv.as_ref().into());
        let mut encrypted_data = data;
        encryptor.apply_keystream(&mut encrypted_data);
        encrypted_data
    }

    fn prepare_output_data(
        &self,
        data_out: &mut BytesMut,
        ephemeral_key: &SecretKey,
        iv: &H128,
        encrypted_data: &[u8],
        tag: &H256,
        total_size: u16,
    ) -> Result<()> {
        data_out.extend_from_slice(&total_size.to_be_bytes());
        data_out.extend_from_slice(
            &PublicKey::from_secret_key(SECP256K1, ephemeral_key).serialize_uncompressed(),
        );
        data_out.extend_from_slice(iv.as_bytes());
        data_out.extend_from_slice(encrypted_data);
        data_out.extend_from_slice(tag.as_bytes());

        Ok(())
    }
}
