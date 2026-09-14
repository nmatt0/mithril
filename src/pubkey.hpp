// pubkey.hpp — recover PUBLIC keys from firmware content.
//
// The secrets pass (derkey.cpp / engine.cpp) hunts *private* key material. This
// module is the front half of the key-weakness pass: it recovers *public* keys —
// from X.509 certificates, SSH public keys, PEM/DER SubjectPublicKeyInfo and
// PKCS#1 RSA public keys, and the public half of any PEM private key — so the
// weakness checks (keyweak.hpp) can answer "is this public key's private half
// obtainable" (leaked/default corpus hit, ROCA, undersized modulus, ...).
//
// For an RSA key we keep the modulus n (big-endian, sign byte stripped) and the
// exponent e, which every weakness check keys on. Non-RSA keys are still recorded
// (algorithm + fingerprint) so a leaked/default corpus match still fires on them.
// All parsing is a bounded ASN.1/DER TLV walk plus base64 — no crypto dependency.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ft {

// How a public key was recovered — drives the human wording and the finding type.
enum class KeyOrigin : uint8_t {
    Certificate,   // X.509 certificate (PEM / DER / PKCS#7 / EFI signature list)
    SshPublicKey,  // an OpenSSH-format public key line (authorized_keys / *.pub)
    PublicKeyInfo, // a PEM/DER SubjectPublicKeyInfo or PKCS#1 RSA public key
    PrivateKey,    // the public half extracted from an embedded private key
};

const char* origin_name(KeyOrigin o);

struct PublicKey {
    std::string algo;        // "RSA" / "EC" / "Ed25519" / "DSA" / "Ed448" / ...
    std::string curve;       // EC curve name when known (e.g. "secp256r1")
    size_t bits = 0;         // modulus/field bit size (RSA modulus, EC field, ...)

    std::vector<uint8_t> n;   // RSA modulus, big-endian, leading zeros stripped
    std::vector<uint8_t> e_be;  // RSA public exponent, big-endian, minimal (may be large)
    uint64_t e = 0;           // RSA public exponent as u64 (0 if it does not fit / non-RSA)

    KeyOrigin origin = KeyOrigin::PublicKeyInfo;
    size_t offset = 0;       // byte offset of the key within its file

    // Fingerprints for the leaked/default corpus lookup (keycorpus.hpp):
    std::string fp_der;      // SHA-256[0:32] of the DER cert / SPKI (whichever applies)
    std::string fp_ssh;      // SHA-256[0:32] of the raw SSH public-key blob (SSH keys)
    std::string fp_modn;     // SHA-256[0:32] of the modulus bytes (BKHASH120-style; RSA)

    // A short redacted label for display (e.g. "RSA-2048 SSH host key").
    std::string label;
};

// Recover every public key from one file's bytes. Text-anchored: PEM blocks
// (CERTIFICATE / PUBLIC KEY / RSA PUBLIC KEY / PRIVATE KEY), OpenSSH public-key
// lines, and — when the whole buffer is one — a bare DER certificate or SPKI.
std::vector<PublicKey> extract_public_keys(std::span<const uint8_t> data);

}  // namespace ft
