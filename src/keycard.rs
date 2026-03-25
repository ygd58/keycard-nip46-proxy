use anyhow::Result;
use secp256k1::{rand::thread_rng, Keypair, Secp256k1, SecretKey};

/// Keycard client — real hardware or mock for testing
pub struct KeycardClient {
    mode: KeycardMode,
}

enum KeycardMode {
    Mock { keypair: Keypair },
    #[cfg(feature = "hardware")]
    Hardware { card: pcsc::Card },
}

impl KeycardClient {
    pub fn connect(pin: &str, mock: bool) -> Result<Self> {
        if mock {
            tracing::warn!("Using MOCK signer — not suitable for production!");
            let secp = Secp256k1::new();
            let keypair = Keypair::new(&secp, &mut thread_rng());
            return Ok(Self {
                mode: KeycardMode::Mock { keypair },
            });
        }

        // Real Keycard via PC/SC
        #[cfg(feature = "hardware")]
        {
            let ctx = pcsc::Context::establish(pcsc::Scope::User)?;
            let mut readers_buf = vec![0u8; 2048];
            let readers = ctx.list_readers(&mut readers_buf)?;
            let reader = readers
                .iter()
                .next()
                .ok_or_else(|| anyhow!("No Keycard found. Check USB connection."))?;

            let (card, _) = ctx.connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)?;
            verify_pin(&card, pin)?;
            return Ok(Self {
                mode: KeycardMode::Hardware { card },
            });
        }

        #[cfg(not(feature = "hardware"))]
        {
            let _ = pin;
            anyhow::bail!(
                "Hardware mode not enabled. Build with --features hardware or use --mock flag."
            );
        }
    }

    pub fn get_public_key(&self) -> Result<String> {
        match &self.mode {
            KeycardMode::Mock { keypair } => {
                let pubkey = keypair.x_only_public_key().0;
                Ok(hex::encode(pubkey.serialize()))
            }
            #[cfg(feature = "hardware")]
            KeycardMode::Hardware { card } => get_pubkey_from_card(card),
        }
    }

    pub fn get_secret_key(&self) -> Result<SecretKey> {
        match &self.mode {
            KeycardMode::Mock { keypair } => Ok(keypair.secret_key()),
            #[cfg(feature = "hardware")]
            KeycardMode::Hardware { .. } => {
                anyhow::bail!("Cannot extract secret key from hardware — use sign() instead")
            }
        }
    }

    pub fn sign(&self, hash: &[u8; 32]) -> Result<Vec<u8>> {
        match &self.mode {
            KeycardMode::Mock { keypair } => {
                
                let secp = Secp256k1::new();
                let msg = secp256k1::Message::from_digest(*hash);
                let sig = secp.sign_schnorr_no_aux_rand(&msg, keypair);
                Ok(sig.serialize().to_vec())
            }
            #[cfg(feature = "hardware")]
            KeycardMode::Hardware { card } => sign_with_card(card, hash),
        }
    }
}

#[cfg(feature = "hardware")]
fn verify_pin(card: &pcsc::Card, pin: &str) -> Result<()> {
    let pin_bytes = pin.as_bytes();
    let mut apdu = vec![0x80, 0x20, 0x00, 0x00, pin_bytes.len() as u8];
    apdu.extend_from_slice(pin_bytes);
    let mut response = vec![0u8; 256];
    let rapdu = card.transmit(&apdu, &mut response)?;
    let sw = u16::from_be_bytes([rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]]);
    if sw != 0x9000 {
        anyhow::bail!("PIN verification failed: SW={:#06x}", sw);
    }
    Ok(())
}

#[cfg(feature = "hardware")]
fn get_pubkey_from_card(card: &pcsc::Card) -> Result<String> {
    let apdu = [0x80, 0xF2, 0x00, 0x00, 0x00];
    let mut response = vec![0u8; 256];
    let rapdu = card.transmit(&apdu, &mut response)?;
    Ok(hex::encode(&rapdu[..32]))
}

#[cfg(feature = "hardware")]
fn sign_with_card(card: &pcsc::Card, hash: &[u8; 32]) -> Result<Vec<u8>> {
    let mut apdu = vec![0x80, 0xC0, 0x00, 0x00, 0x20];
    apdu.extend_from_slice(hash);
    let mut response = vec![0u8; 256];
    let rapdu = card.transmit(&apdu, &mut response)?;
    let sw = u16::from_be_bytes([rapdu[rapdu.len() - 2], rapdu[rapdu.len() - 1]]);
    if sw != 0x9000 {
        anyhow::bail!("Signing failed: SW={:#06x}", sw);
    }
    Ok(rapdu[..rapdu.len() - 2].to_vec())
}
