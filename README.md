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
