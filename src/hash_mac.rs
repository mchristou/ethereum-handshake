use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use ethereum_types::{H128, H256};
use sha3::{Digest, Keccak256};

#[derive(Debug)]
pub struct HashMac {
    secret: H256,
    hasher: Keccak256,
}

impl HashMac {
    pub fn new(secret: H256) -> Self {
        Self {
            secret,
            hasher: Keccak256::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data)
    }

    pub fn digest(&self) -> H128 {
        H128::from_slice(&self.hasher.clone().finalize()[..16])
    }

    pub fn compute_header(&mut self, header_cipher_text: &[u8]) {
        let mut header_mac_seed = self.digest().to_fixed_bytes();

        self.compute(&mut header_mac_seed, header_cipher_text);
    }

    pub fn compute_frame(&mut self, body_ciphertext: &[u8]) {
        self.hasher.update(body_ciphertext);

        let seed = self.digest();
        self.compute(&mut seed.to_fixed_bytes(), seed.as_ref());
    }

    fn compute(&mut self, seed: &mut [u8], cipher_text: &[u8]) {
        self.encrypt(seed);

        for i in 0..cipher_text.len() {
            seed[i] ^= cipher_text[i];
        }

        self.hasher.update(seed);
    }

    fn encrypt(&self, data: &mut [u8]) {
        let cipher = aes::Aes256::new(self.secret.as_ref().into());
        cipher.encrypt_block(GenericArray::from_mut_slice(data));
    }
}
