// certid.hpp — X.509 certificate extraction + fingerprinting.
//
// The shared primitive behind the boot-key corpus match: pull the DER
// certificate out of the container a device ships it in, and fingerprint it the
// standard way (SHA-256 of the DER cert). Two containers:
//   - UEFI EFI_SIGNATURE_LIST (PK/KEK/db variable data) -> each X.509 cert
//   - PKCS#7 SignedData (an APK/OTA `*.RSA` signature block) -> the signer cert
// A raw DER/PEM certificate is handled directly. All parsing is a bounded DER
// TLV walk (no crypto dependency); SHA-256 is src/sha256.cpp.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace ft {

// SHA-256 (first 32 lowercase hex chars) of a DER certificate's bytes — the
// fingerprint the corpus (bootkeys) is keyed by.
std::string cert_fingerprint(std::span<const uint8_t> der_cert);

// Every X.509 certificate embedded in an EFI_SIGNATURE_LIST (or a run of them,
// as a UEFI PK/KEK/db variable stores). Returns copies of each cert's DER bytes.
std::vector<std::vector<uint8_t>> certs_in_efi_signature_list(std::span<const uint8_t> data);

// The first (signer) X.509 certificate in a DER PKCS#7 SignedData; empty if not
// a PKCS#7 or no certificate is present.
std::vector<uint8_t> cert_from_pkcs7(std::span<const uint8_t> der);

// If `data` is a PEM or bare-DER X.509 certificate, its DER bytes; else empty.
std::vector<uint8_t> cert_from_any(std::span<const uint8_t> data);

}  // namespace ft
