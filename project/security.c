#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

static uint8_t client_nonce[NONCE_SIZE];
static uint8_t server_nonce[NONCE_SIZE];

static uint64_t read_be_uint(const uint8_t *bytes, size_t nbytes)
{
    UNUSED(bytes);
    UNUSED(nbytes);
    // TODO: parse an unsigned integer from a big-endian byte sequence.
    // Hint: this is used for certificate lifetime fields.
    return 0;
}

static bool parse_lifetime_window(const tlv *life, uint64_t *start_ts, uint64_t *end_ts)
{
    UNUSED(life);
    UNUSED(start_ts);
    UNUSED(end_ts);
    // TODO: decode [not_before || not_after] from CERTIFICATE/LIFETIME.
    // Return false on malformed input (NULL pointers, wrong length, invalid range).
    return false;
}

static void enforce_lifetime_valid(const tlv *life)
{
    UNUSED(life);
    // TODO: enforce lifetime validity against current time.
    // Exit with code 1 for invalid/expired cert, code 6 for malformed time inputs.
}

void init_sec(int initial_state, char *peer_host, bool bad_mac)
{
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();

    // TODO: initialize keys and role-specific state.
    // Client side: load CA public key and prepare ephemeral keypair.
    // Server side: load certificate and prepare ephemeral keypair.
    if (initial_state == CLIENT_CLIENT_HELLO_SEND)
    {
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
    }
    else
    {
        load_certificate("server_cert.bin");
        generate_private_key();
        derive_public_key();
    }
}

ssize_t input_sec(uint8_t *out_buf, size_t out_cap)
{
    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        print("SEND CLIENT HELLO");
        // TODO: build CLIENT_HELLO with VERSION_TAG, NONCE, and PUBLIC_KEY TLVs.
        // Save client nonce for later key derivation and advance to CLIENT_SERVER_HELLO_AWAIT.
        client_hello = create_tlv(CLIENT_HELLO);

        tlv *version = create_tlv(VERSION_TAG);
        uint8_t ver = PROTOCOL_VERSION;
        add_val(version, &ver, 1);
        add_tlv(client_hello, version);

        tlv *nonce = create_tlv(NONCE);
        generate_nonce(client_nonce, NONCE_SIZE);
        add_val(nonce, client_nonce, NONCE_SIZE);

        add_tlv(client_hello, nonce);

        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(client_hello, pub_key);

        uint16_t len = serialize_tlv(out_buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t)len;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");
        // TODO: build SERVER_HELLO with NONCE, CERTIFICATE, PUBLIC_KEY, HANDSHAKE_SIGNATURE.
        // Sign the expected handshake transcript, derive session keys, then enter DATA_STATE.
        server_hello = create_tlv(SERVER_HELLO);

        tlv *nonce = create_tlv(NONCE);
        generate_nonce(server_nonce, NONCE_SIZE);
        add_val(nonce, server_nonce, NONCE_SIZE);
        add_tlv(server_hello, nonce);

        tlv *cert = create_tlv(CERTIFICATE);
        add_val(cert, certificate, cert_size);
        add_tlv(server_hello, cert);

        tlv *pub_key = create_tlv(PUBLIC_KEY);
        add_val(pub_key, public_key, pub_key_size);
        add_tlv(server_hello, pub_key);

        /*
        from implementation guide:

        "You must verify the signature over the Serialized TLVs.
        Create a temporary buffer, serialize the Client Hello TLV,
        then append the serialized Server Nonce TLV,
        then the serialized Ephemeral Key TLV.
        Sign this combined buffer."
        */
        tlv *handshake_sig = create_tlv(HANDSHAKE_SIGNATURE);
        uint8_t sig_data[512];
        uint16_t offset = 0;
        offset += serialize_tlv(sig_data + offset, client_hello);
        offset += serialize_tlv(sig_data + offset, nonce);
        offset += serialize_tlv(sig_data + offset, pub_key);

        /*
        tip from implementation guide:
        "The Server needs to switch between keys.
        It normally uses its Ephemeral Key (for deriving secrets),
        but temporarily needs its Identity Key (from server_key.bin) to sign the handshake.
        Use get_private_key() and set_private_key() to save/restore the ephemeral key
        before/after loading the identity key."
        */
        EVP_PKEY *ephemeral = get_private_key();
        load_private_key("server_key.bin");
        uint8_t sig[256];
        size_t sig_size = sign(sig, sig_data, offset);
        set_private_key(ephemeral);

        add_val(handshake_sig, sig, sig_size);
        add_tlv(server_hello, handshake_sig);

        uint16_t len = serialize_tlv(out_buf, server_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t)len;
    }
    case DATA_STATE:
    {
        UNUSED(out_buf);
        UNUSED(out_cap);
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        return (ssize_t)0;
    }
    default:
        return (ssize_t)0;
    }
}

void output_sec(uint8_t *in_buf, size_t in_len)
{
    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        print("RECV CLIENT HELLO");
        // TODO: parse CLIENT_HELLO, validate required fields and protocol version.
        // Load peer ephemeral key, store client nonce, and transition to SERVER_SERVER_HELLO_SEND.
        client_hello = deserialize_tlv(in_buf, in_len);
        if (!client_hello)
            exit(6);

        tlv *version = get_tlv(client_hello, VERSION_TAG);
        if (!version || version->length != 1 || version->val[0] != PROTOCOL_VERSION)
            exit(6);

        tlv *nonce = get_tlv(client_hello, NONCE);
        if (!nonce || nonce->length != NONCE_SIZE)
            exit(6);
        memcpy(client_nonce, nonce->val, NONCE_SIZE);

        tlv *peer_key = get_tlv(client_hello, PUBLIC_KEY);
        if (!peer_key)
            exit(6);
        load_peer_public_key(peer_key->val, peer_key->length);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        print("RECV SERVER HELLO");
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).
        break;
    }
    case DATA_STATE:
    {
        UNUSED(in_buf);
        UNUSED(in_len);
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
