use anyhow::{anyhow, bail, Result};
use secp256k1::{rand::thread_rng, Keypair, Secp256k1, SecretKey};
use std::io::Write;
use std::process::{Command, Stdio};

pub struct KeycardClient {
    mode: KeycardMode,
}

enum KeycardMode {
    Mock { keypair: Keypair },
    Hardware { pin: String, pairing_pass: String, binary: String },
}

impl KeycardClient {
    pub fn connect(pin: &str, mock: bool) -> Result<Self> {
        if mock {
            tracing::warn!("Using MOCK signer — not suitable for production!");
            let secp = Secp256k1::new();
            let keypair = Keypair::new(&secp, &mut thread_rng());
            return Ok(Self { mode: KeycardMode::Mock { keypair } });
        }

        let binary = Self::find_keycard_cli()?;
        tracing::info!("Using keycard-cli: {}", binary);

        Ok(Self {
            mode: KeycardMode::Hardware {
                pin: pin.to_string(),
                pairing_pass: "KeycardDefaultPairing".to_string(),
                binary,
            },
        })
    }

    fn find_keycard_cli() -> Result<String> {
        let home = std::env::var("HOME").unwrap_or_default();
        let candidates = [
            format!("{}/go/bin/keycard-cli", home),
            "keycard-cli".to_string(),
        ];

        for candidate in &candidates {
            if Command::new(candidate).arg("version").output().is_ok() {
                return Ok(candidate.clone());
            }
        }

        bail!("keycard-cli not found. Install: go install github.com/status-im/keycard-cli@latest")
    }

    fn run_shell_commands(&self, binary: &str, commands: &str) -> Result<String> {
        let mut child = Command::new(binary)
            .arg("shell")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| anyhow!("Failed to spawn keycard-cli: {}", e))?;

        if let Some(stdin) = child.stdin.take() {
            let mut stdin = stdin;
            stdin.write_all(commands.as_bytes())
                .map_err(|e| anyhow!("Failed to write to keycard-cli stdin: {}", e))?;
        }

        let output = child.wait_with_output()
            .map_err(|e| anyhow!("keycard-cli error: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();

        if !output.status.success() && stdout.is_empty() {
            bail!("keycard-cli failed: {}", stderr);
        }

        Ok(stdout)
    }

    pub fn get_public_key(&self) -> Result<String> {
        match &self.mode {
            KeycardMode::Mock { keypair } => {
                let pubkey = keypair.x_only_public_key().0;
                Ok(hex::encode(pubkey.serialize()))
            }
            KeycardMode::Hardware { pin, pairing_pass, binary } => {
                let commands = format!(
                    "keycard-select\nkeycard-set-secrets {pin} 123456789012 {pairing_pass}\nkeycard-pair\nkeycard-open-secure-channel\nkeycard-verify-pin {pin}\nkeycard-derive-key m/44\'/1237\'/0\'/0/0\nkeycard-export-key\n"
                );

                let output = self.run_shell_commands(binary, &commands)?;

                // Parse public key from output
                for line in output.lines() {
                    if line.contains("public-key") || line.contains("PublicKey") {
                        if let Some(key) = line.split_whitespace().last() {
                            if key.len() == 66 || key.len() == 64 {
                                return Ok(key.to_string());
                            }
                        }
                    }
                }
                bail!("Could not parse public key from output:\n{}", output)
            }
        }
    }

    pub fn get_secret_key(&self) -> Result<SecretKey> {
        match &self.mode {
            KeycardMode::Mock { keypair } => Ok(keypair.secret_key()),
            KeycardMode::Hardware { .. } => {
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
            KeycardMode::Hardware { pin, pairing_pass, binary } => {
                let hash_hex = hex::encode(hash);
                let commands = format!(
                    "keycard-select\nkeycard-set-secrets {pin} 123456789012 {pairing_pass}\nkeycard-pair\nkeycard-open-secure-channel\nkeycard-verify-pin {pin}\nkeycard-derive-key m/44\'/1237\'/0\'/0/0\nkeycard-sign {hash_hex}\n"
                );

                let output = self.run_shell_commands(binary, &commands)?;

                // Parse signature from output
                for line in output.lines() {
                    if line.contains("signature") || line.contains("Signature") {
                        if let Some(sig_hex) = line.split_whitespace().last() {
                            if sig_hex.len() >= 128 {
                                return Ok(hex::decode(sig_hex)?);
                            }
                        }
                    }
                }
                bail!("Could not parse signature from output:\n{}", output)
            }
        }
    }
}
