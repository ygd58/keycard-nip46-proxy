use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
pub struct Nip46Request {
    pub id: String,
    pub method: String,
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Nip46Response {
    pub id: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NostrEvent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pubkey: Option<String>,
    pub created_at: i64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sig: Option<String>,
}

impl NostrEvent {
    pub fn compute_id(&self) -> [u8; 32] {
        let serialized = serde_json::json!([
            0,
            self.pubkey,
            self.created_at,
            self.kind,
            self.tags,
            self.content
        ])
        .to_string();
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hasher.finalize().into()
    }
}

pub mod nip04 {
    use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};
    use aes::Aes256;
    use base64::{engine::general_purpose, Engine};
    use secp256k1::{ecdh::SharedSecret, PublicKey, SecretKey};

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    type Aes256CbcDec = cbc::Decryptor<Aes256>;

    pub fn shared_secret(our_sk: &SecretKey, their_pk: &PublicKey) -> [u8; 32] {
        SharedSecret::new(their_pk, our_sk).secret_bytes()
    }

    pub fn encrypt(key: &[u8; 32], plaintext: &str) -> String {
        let iv = rand_iv();
        let enc = Aes256CbcEnc::new(key.into(), &iv.into());
        let plaintext_bytes = plaintext.as_bytes();
        // Allocate buffer with padding space (block size = 16)
        let buf_len = plaintext_bytes.len() + 16;
        let mut buf = vec![0u8; buf_len];
        buf[..plaintext_bytes.len()].copy_from_slice(plaintext_bytes);
        let ciphertext = enc
            .encrypt_padded_mut::<Pkcs7>(&mut buf, plaintext_bytes.len())
            .unwrap_or(&[]);
        format!(
            "{}?iv={}",
            general_purpose::STANDARD.encode(ciphertext),
            general_purpose::STANDARD.encode(iv)
        )
    }

    pub fn decrypt(key: &[u8; 32], payload: &str) -> anyhow::Result<String> {
        let parts: Vec<&str> = payload.splitn(2, "?iv=").collect();
        anyhow::ensure!(parts.len() == 2, "invalid NIP-04 payload");
        let mut ciphertext = general_purpose::STANDARD.decode(parts[0])?;
        let iv_bytes = general_purpose::STANDARD.decode(parts[1])?;
        let iv: [u8; 16] = iv_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid IV length"))?;
        let dec = Aes256CbcDec::new(key.into(), &iv.into());
        let plaintext = dec
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .map_err(|e| anyhow::anyhow!("decrypt error: {e}"))?;
        Ok(String::from_utf8(plaintext.to_vec())?)
    }

    fn rand_iv() -> [u8; 16] {
        use secp256k1::rand::RngCore;
        let mut iv = [0u8; 16];
        secp256k1::rand::thread_rng().fill_bytes(&mut iv);
        iv
    }
}
