mod secure_channel;
mod keycard;
mod nip46;
mod daemon;
mod policy;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "keycard-nip46-proxy")]
#[command(about = "NIP-46 Nostr remote signer proxy backed by Keycard hardware")]
struct Args {
    /// Nostr relay URL
    #[arg(short, long, default_value = "wss://relay.damus.io")]
    relay: String,

    /// Keycard PIN
    #[arg(short, long, env = "KEYCARD_PIN")]
    pin: String,

    /// Auto-approve all signing requests (for testing only)
    #[arg(long, default_value_t = false)]
    auto_approve: bool,

    /// Use mock signer instead of real Keycard (for testing without hardware)
    #[arg(long, default_value_t = false)]
    mock: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    tracing::info!("Starting Keycard NIP-46 Proxy");
    tracing::info!("Relay: {}", args.relay);

    let card = keycard::KeycardClient::connect(&args.pin, args.mock)?;
    let pubkey = card.get_public_key()?;
    tracing::info!("Keycard pubkey: {}", pubkey);

    let policy = policy::ApprovalPolicy::new(args.auto_approve);
    daemon::run(args.relay, card, policy, pubkey).await?;

    Ok(())
}
