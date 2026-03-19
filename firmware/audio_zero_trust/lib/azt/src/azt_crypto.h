#pragma once

#include <Arduino.h>
#include <cstdint>
#include <vector>

namespace azt {

String b64(const uint8_t* data, size_t len);
String hex_lower(const uint8_t* data, size_t len);

void append_u16_be(std::vector<uint8_t>& out, uint16_t v);
void append_u32_be(std::vector<uint8_t>& out, uint32_t v);

bool sha256_bytes(const uint8_t* msg, size_t msg_len, uint8_t out32[32]);
bool compute_pubkey_spki_sha256_hex(const String& pub_pem, String& out_hex);
bool rsa_oaep_sha256_encrypt_pub(const uint8_t* pub_pem,
                                 size_t pub_len,
                                 const uint8_t* in,
                                 size_t in_len,
                                 std::vector<uint8_t>& out);
bool b64_decode_vec(const String& in, std::vector<uint8_t>& out);
bool verify_rsa_pss_sha256_signature(const String& pub_pem,
                                     const std::vector<uint8_t>& payload,
                                     const String& sig_b64);
bool aes256_gcm_encrypt(const uint8_t* key32,
                        const uint8_t* nonce12,
                        const uint8_t* plaintext,
                        size_t plaintext_len,
                        std::vector<uint8_t>& ciphertext,
                        uint8_t tag16[16]);

}  // namespace azt
