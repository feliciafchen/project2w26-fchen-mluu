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
    // TODO: parse an unsigned integer from a big-endian byte sequence.
    // Hint: this is used for certificate lifetime fields.
    uint64_t result = 0;
    for (size_t i = 0; i < nbytes; i++)
    {
        result = (result << 8) | bytes[i];
    }
    return result;
}

static bool parse_lifetime_window(const tlv *life, uint64_t *start_ts, uint64_t *end_ts)
{
    // TODO: decode [not_before || not_after] from CERTIFICATE/LIFETIME.
    // Return false on malformed input (NULL pointers, wrong length, invalid range).
    if (!life || !start_ts || !end_ts)
        return false;
    if (life->length != 16 || life->val == NULL)
        return false;

    *start_ts = read_be_uint(life->val, 8);
    *end_ts = read_be_uint(life->val + 8, 8);

    if (*start_ts >= *end_ts)
        return false;

    return true;
}

static void enforce_lifetime_valid(const tlv *life)
{
    // TODO: enforce lifetime validity against current time.
    // Exit with code 1 for invalid/expired cert, code 6 for malformed time inputs.
    uint64_t not_before, not_after;
    if (!parse_lifetime_window(life, &not_before, &not_after))
        exit(6);

    uint64_t now = (uint64_t)time(NULL);
    if (now < not_before || now > not_after)
        exit(1);
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
        uint8_t sig_data[2048];
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

        derive_secret();
        uint8_t salt[64];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        uint16_t len = serialize_tlv(out_buf, server_hello);
        state_sec = DATA_STATE;
        return (ssize_t)len;
    }
    case DATA_STATE:
    {
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        // Sending Data
        ssize_t input_len = input_io(out_buf, out_cap);
        if (input_len < 0)
        {
            exit(1);
        }

        // Create data tlv fields
        uint8_t iv_buf[IV_SIZE];
        uint8_t mac[MAC_SIZE];
        uint8_t cipher_buf[2048];
        
        // Encrypt
        size_t cipher_len = encrypt_data(iv_buf, cipher_buf, out_buf, (size_t)input_len);

        tlv *iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv_buf, IV_SIZE);
        tlv *cipher_tlv = create_tlv(CIPHERTEXT);
        add_val(cipher_tlv, cipher_buf, cipher_len);
        tlv *mac_tlv = create_tlv(MAC);

        // Serialize data and MAC
        uint8_t data[2048];
        uint16_t data_len = 0;
        data_len += serialize_tlv(data + data_len, iv_tlv);
        data_len += serialize_tlv(data + data_len, cipher_tlv);

        hmac(mac, data, data_len);
        
        // If inc_mac is true, intentionally corrupt the MAC for testing
        if (inc_mac)
        {
            mac[0] ^= 0xFF;
        }
        
        add_val(mac_tlv, mac, MAC_SIZE);

        tlv *data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, cipher_tlv);
        add_tlv(data_tlv, mac_tlv);

        uint16_t len = serialize_tlv(out_buf, data_tlv);
        return (ssize_t)len;
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
        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).
        server_hello = deserialize_tlv(in_buf, in_len);
        if (!server_hello)
        {
            exit(6);
        }
        // Parse server hello
        tlv *nonce = get_tlv(server_hello, NONCE);
        if (!nonce)
        {
            exit(6);
        }

        tlv *cert = get_tlv(server_hello, CERTIFICATE);
        if (!cert)
        {
            exit(6);
        }

        tlv *pub_key = get_tlv(server_hello, PUBLIC_KEY);
        if (!pub_key)
        {
            exit(6);
        }
        load_peer_public_key(pub_key->val, pub_key->length);

        tlv *handshake_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
        if (!handshake_sig)
        {
            exit(6);
        }

        // Check 1: Certificate Validity
        // Parse Cert and save in cert_data
        uint8_t cert_data[2048];
        uint16_t data_len = 0;

        tlv *dns = get_tlv(cert, DNS_NAME);
        if (!dns)
        {
            exit(6);
        }
        data_len += serialize_tlv(cert_data + data_len, dns);

        tlv *cert_pub_key = get_tlv(cert, PUBLIC_KEY);
        if (!cert_pub_key)
        {
            exit(6);
        }
        data_len += serialize_tlv(cert_data + data_len, cert_pub_key);

        tlv *lifetime = get_tlv(cert, LIFETIME);
        if (!lifetime)
        {
            exit(6);
        }
        data_len += serialize_tlv(cert_data + data_len, lifetime);

        tlv *cert_sig = get_tlv(cert, SIGNATURE);
        if (!cert_sig)
        {
            exit(6);
        }

        if (!verify(cert_sig->val, cert_sig->length, cert_data, data_len, ec_ca_public_key))
        {
            exit(1);
        }
        // Lifetime validation
        enforce_lifetime_valid(lifetime);

        // Check 2: DNS name match
        if (hostname == NULL || dns->length != strlen(hostname) || memcmp(dns->val, hostname, dns->length) != 0){
            exit(2);
        }

        // handshake validation
        uint8_t hs_data[2048];
        uint16_t hs_data_len = 0;
        hs_data_len += serialize_tlv(hs_data + hs_data_len, client_hello);

        tlv *s_nonce = get_tlv(server_hello, NONCE);
        if (!s_nonce)
        {
            exit(6);
        }
        hs_data_len += serialize_tlv(hs_data + hs_data_len, s_nonce);

        tlv *s_pubkey = get_tlv(server_hello, PUBLIC_KEY);
        if (!s_pubkey)
        {
            exit(6);
        }
        hs_data_len += serialize_tlv(hs_data + hs_data_len, s_pubkey);

        tlv *hs_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
        if (!hs_sig)
        {
            exit(6);
        }

        EVP_PKEY *identity_key = NULL;
        load_peer_public_key(cert_pub_key->val, cert_pub_key->length);
        identity_key = ec_peer_public_key;

        if (!verify(hs_sig->val, hs_sig->length, hs_data, hs_data_len, identity_key))
        {
            exit(3);
        }

        derive_secret();
        uint8_t salt[64];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, s_nonce->val, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        // TODO: parse DATA, verify MAC before decrypting, then output plaintext.
        // Required exit code: bad MAC(5), malformed(6).
        tlv *data_tlv = deserialize_tlv(in_buf, in_len);
        if(!data_tlv){
            exit(6);
        }

        tlv *iv = get_tlv(data_tlv, IV);
        if (!iv)
        {
            exit(6);
        }

        tlv *cipher = get_tlv(data_tlv, CIPHERTEXT);
        if (!cipher)
        {
            exit(6);
        }

        tlv *mac = get_tlv(data_tlv, MAC);
        if (!mac)
        {
            exit(6);
        }

        uint8_t computed_mac[MAC_SIZE];
        uint8_t data[2048];
        uint16_t data_len = 0;
        data_len += serialize_tlv(data + data_len, iv);
        data_len += serialize_tlv(data + data_len, cipher);

        hmac(computed_mac, data, data_len);

        if (memcmp(computed_mac, mac->val, MAC_SIZE) != 0)
        {
            exit(5);
        }

        uint8_t output[2048];
        size_t output_len = decrypt_cipher(output, cipher->val, cipher->length, iv->val);

        output_io(output, output_len);
        break;
    }
    default:
        // TODO: handle unexpected states.
        break;
    }
}
