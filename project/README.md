# CS 118 Winter 26 Project 2

## Implementation Notes

- `init_sec`: The client loads the CA public key (`ca_public_key.bin`) and generates an ephemeral ECDH keypair. The server loads its certificate (`server_cert.bin`) and identity key (`server_key.bin`), then also generates an ephemeral ECDH keypair.

- `CLIENT_CLIENT_HELLO_SEND`: Builds and serializes a `CLIENT_HELLO` TLV with a `VERSION_TAG`, a randomly generated 32-byte `NONCE`, and the client's ephemeral `PUBLIC_KEY`. We then transition to `CLIENT_SERVER_HELLO_AWAIT`.

- `SERVER_SERVER_HELLO_SEND`:
- `CLIENT_SERVER_HELLO_AWAIT`:
- `SERVER_CLIENT_HELLO_AWAIT`:
- `DATA_STATE`:
