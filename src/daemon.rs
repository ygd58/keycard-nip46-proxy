use futures_util::{SinkExt, StreamExt};
use secp256k1::{PublicKey, SecretKey};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

use crate::keycard::KeycardClient;
use crate::nip46::{nip04, Nip46Request, Nip46Response, NostrEvent};
use crate::policy::ApprovalPolicy;

pub async fn run(
    relay_url: String,
    card: KeycardClient,
    policy: ApprovalPolicy,
    pubkey: String,
) -> anyhow::Result<()> {
    info!("Connecting to relay: {}", relay_url);
    let (ws_stream, _) = connect_async(&relay_url).await?;
    let (mut write, mut read) = ws_stream.split();

    // Subscribe to NIP-46 messages sent to our pubkey
    let sub = serde_json::json!([
        "REQ",
        "nip46-sub",
        {"kinds": [24133], "#p": [pubkey]}
    ]);
    write.send(Message::Text(sub.to_string())).await?;
    info!("Subscribed to NIP-46 messages for pubkey: {}", pubkey);

    // Print connection URI for the user
    let connect_uri = format!("nostrconnect://{}?relay={}", pubkey, relay_url);
    println!("\n🔑 Keycard NIP-46 Proxy ready!");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("Connection URI:\n{}", connect_uri);
    println!("Paste this into your NIP-46 client (Coracle, Snort, noStrudel).");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");

    // Get our ephemeral secret key for NIP-04 encryption
    let our_sk = card.get_secret_key().ok();

    while let Some(msg) = read.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                if let Err(e) =
                    handle_message(&text, &card, &policy, &pubkey, our_sk.as_ref(), &mut write)
                        .await
                {
                    error!("Message handling error: {}", e);
                }
            }
            Ok(Message::Ping(p)) => {
                let _ = write.send(Message::Pong(p)).await;
            }
            Err(e) => {
                warn!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    Ok(())
}

async fn handle_message(
    raw: &str,
    card: &KeycardClient,
    policy: &ApprovalPolicy,
    our_pubkey: &str,
    our_sk: Option<&SecretKey>,
    write: &mut (impl SinkExt<Message, Error = impl std::fmt::Debug> + Unpin),
) -> anyhow::Result<()> {
    let parsed: serde_json::Value = serde_json::from_str(raw)?;
    if parsed[0] != "EVENT" {
        return Ok(());
    }

    let event = &parsed[2];
    let sender_pubkey = event["pubkey"].as_str().unwrap_or("");
    let content_str = event["content"].as_str().unwrap_or("");

    // Decrypt NIP-04 content if we have our secret key
    let decrypted = if let Some(sk) = our_sk {
        let their_pk = parse_pubkey(sender_pubkey)?;
        let shared = nip04::shared_secret(sk, &their_pk);
        nip04::decrypt(&shared, content_str)?
    } else {
        content_str.to_string()
    };

    let request: Nip46Request = serde_json::from_str(&decrypted)?;
    info!("NIP-46 request: method={}", request.method);

    let response = match request.method.as_str() {
        "connect" => {
            info!("Client connected: {}", sender_pubkey);
            Nip46Response {
                id: request.id,
                result: Some(serde_json::json!("ack")),
                error: None,
            }
        }
        "get_public_key" => Nip46Response {
            id: request.id,
            result: Some(serde_json::json!(our_pubkey)),
            error: None,
        },
        "sign_event" => {
            let event_json = request.params[0].to_string();

            if !policy.approve_sign(&event_json) {
                info!("Signing request rejected by user");
                return Ok(());
            }

            let mut nostr_event: NostrEvent = serde_json::from_str(&event_json)?;
            nostr_event.pubkey = Some(our_pubkey.to_string());
            let hash = nostr_event.compute_id();
            let sig = card.sign(&hash)?;

            nostr_event.id = Some(hex::encode(&hash));
            nostr_event.sig = Some(hex::encode(&sig));

            info!("Event signed: id={}", nostr_event.id.as_deref().unwrap_or("?"));

            Nip46Response {
                id: request.id,
                result: Some(serde_json::to_value(&nostr_event)?),
                error: None,
            }
        }
        other => {
            warn!("Unsupported method: {}", other);
            Nip46Response {
                id: request.id,
                result: None,
                error: Some(format!("Unsupported method: {}", other)),
            }
        }
    };

    // Encrypt and publish response
    let response_json = serde_json::to_string(&response)?;
    let content = if let Some(sk) = our_sk {
        let their_pk = parse_pubkey(sender_pubkey)?;
        let shared = nip04::shared_secret(sk, &their_pk);
        nip04::encrypt(&shared, &response_json)
    } else {
        response_json.clone()
    };

    let reply_event = serde_json::json!([
        "EVENT",
        {
            "kind": 24133,
            "content": content,
            "tags": [["p", sender_pubkey]],
            "created_at": std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            "pubkey": our_pubkey,
        }
    ]);

    write
        .send(Message::Text(reply_event.to_string()))
        .await
        .map_err(|e| anyhow::anyhow!("send error: {:?}", e))?;

    Ok(())
}

fn parse_pubkey(hex_str: &str) -> anyhow::Result<PublicKey> {
    let bytes = hex::decode(hex_str)?;
    // Handle both compressed (33 byte) and x-only (32 byte) pubkeys
    let full_bytes = if bytes.len() == 32 {
        let mut prefixed = vec![0x02];
        prefixed.extend_from_slice(&bytes);
        prefixed
    } else {
        bytes
    };
    PublicKey::from_slice(&full_bytes).map_err(|e| anyhow::anyhow!("invalid pubkey: {e}"))
}
