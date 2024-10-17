use crate::hash_mac::HashMac;

pub type Aes128Ctr64BE = ctr::Ctr64BE<aes::Aes128>;
pub type Aes256Ctr64BE = ctr::Ctr64BE<aes::Aes256>;

pub struct Secrets {
    pub ingress_mac: HashMac,
    pub egress_mac: HashMac,
    pub ingress_aes: Aes256Ctr64BE,
    pub egress_aes: Aes256Ctr64BE,
}
