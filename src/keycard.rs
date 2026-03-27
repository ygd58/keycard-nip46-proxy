use anyhow::{anyhow, bail, Result};
use secp256k1::{rand::thread_rng, Keypair, Secp256k1, SecretKey};
use std::process::Command;

pub struct KeycardClient {
    mode: KeycardMode,
}

enum KeycardMode {
    Mock { keypair: Keypair },
    Cli { pin: String, binary: String },
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

        // Use keycard-cli for real card operations
        let binary = Self::find_keycard_cli()?;
        tracing::info!("Using keycard-cli: {}", binary);

        // Test connection
        let output = Command::new(&binary)
            .arg("info")
            .output()
            .map_err(|e| anyhow!("Failed to run keycard-cli: {}", e))?;

        if !output.status.success() {
            bail!(
                "keycard-cli info failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        tracing::info!("Keycard connected successfully");

        Ok(Self {
            mode: KeycardMode::Cli {
                pin: pin.to_string(),
                binary,
            },
        })
    }

    fn find_keycard_cli() -> Result<String> {
        // Check common locations
        let candidates = [
            "keycard-cli",
            &format!("{}/.cargo/bin/keycard-cli", std::env::var("HOME").unwrap_or_default()),
            &format!("{}/go/bin/keycard-cli", std::env::var("HOME").unwrap_or_default()),
        ];

        for candidate in &candidates {
            if Command::new(candidate).arg("version").output().is_ok() {
                return Ok(candidate.to_string());
            }
        }

        bail!(
            "keycard-cli not found. Install with: go install github.com/status-im/keycard-cli@latest"
        )
    }

    pub fn get_public_key(&self) -> Result<String> {
        match &self.mode {
            KeycardMode::Mock { keypair } => {
                let pubkey = keypair.x_only_public_key().0;
                Ok(hex::encode(pubkey.serialize()))
            }
            KeycardMode::Cli { pin, binary } => {
                // Use keycard-cli shell to get public key
                let output = Command::new(binary)
                    .args(["shell", "--pin", pin])
                    .output()
                    .map_err(|e| anyhow!("keycard-cli failed: {}", e))?;

                let stdout = String::from_utf8_lossy(&output.stdout);
                // Parse public key from output
                for line in stdout.lines() {
                    if line.contains("Public Key") || line.contains("public-key") {
                        if let Some(key) = line.split(':').last() {
                            return Ok(key.trim().to_string());
                        }
                    }
                }
                bail!("Could not parse public key from keycard-cli output")
            }
        }
    }

    pub fn get_secret_key(&self) -> Result<SecretKey> {
        match &self.mode {
            KeycardMode::Mock { keypair } => Ok(keypair.secret_key()),
            KeycardMode::Cli { .. } => {
                bail!("Cannot extract secret key from hardware — use sign() instead")
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
            KeycardMode::Cli { pin, binary } => {
                // Use keycard-cli to sign the hash
                let hash_hex = hex::encode(hash);
                let output = Command::new(binary)
                    .args(["shell", "--pin", pin])
                    .output()
                    .map_err(|e| anyhow!("keycard-cli sign failed: {}", e))?;

                if !output.status.success() {
                    bail!(
                        "keycard-cli sign failed: {}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                }

                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    if line.contains("Signature") || line.contains("signature") {
                        if let Some(sig_hex) = line.split(':').last() {
                            return Ok(hex::decode(sig_hex.trim())?);
                        }
                    }
                }
                bail!("Could not parse signature from keycard-cli output")
            }
        }
    }
}


