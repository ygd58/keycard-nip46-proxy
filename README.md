# keycard-nip46-proxy

A NIP-46 Nostr remote signer proxy backed by Keycard hardware security. The private key never leaves the card's secure element.

## Features

- connect, get_public_key, sign_event NIP-46 methods
- NIP-04 encrypted relay communication
- Interactive CLI approval policy (approve/reject per event)
- Mock signer for testing without hardware
- Keycard hardware support via --features hardware

## Usage

Mock mode (no hardware needed):

    cargo run -- --pin 123456 --mock --relay wss://nos.lol

Hardware mode (real Keycard):

    sudo apt install libpcsclite-dev
    cargo build --features hardware
    ./target/debug/keycard-nip46-proxy --pin YOUR_PIN --relay wss://nos.lol

Paste the printed nostrconnect:// URI into Coracle, Snort, or noStrudel.

## License

MIT OR Apache-2.0

## Demo Output

Running in mock mode:

    $ cargo run -- --pin 123456 --mock --relay wss://nos.lol
    INFO  Starting Keycard NIP-46 Proxy
    INFO  Relay: wss://nos.lol
    WARN  Using MOCK signer — not suitable for production!
    INFO  Keycard pubkey: 410a0b2ad4bb0b2ec00c538fb322cd8f932629b8...
    INFO  Subscribed to NIP-46 messages for pubkey: 410a0b...

    🔑 Keycard NIP-46 Proxy ready!
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    Connection URI:
    nostrconnect://410a0b2ad4bb0b2ec...?relay=wss://nos.lol
    Paste this into your NIP-46 client (Coracle, Snort, noStrudel).
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

## Connect to Coracle

1. Start the daemon
2. Copy the nostrconnect:// URI
3. Open https://coracle.social -> Settings -> Remote Signers -> Add
4. Paste URI -> compose a note -> approve in terminal
