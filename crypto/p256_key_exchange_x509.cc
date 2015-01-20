// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange_x509.h"
#include "net/quic/crypto/p256_key_exchange.h"

#include <openssl/x509.h>

namespace crypto {

base::StringPiece P256KeyExchangeX509::GetX509Public() const {
	if (!public_key_.empty()) return public_key_;

  // We get the public in X.509 format from the private key
  crypto::ScopedEVP_PKEY pkey { EVP_PKEY_new() };
  EVP_PKEY_set1_EC_KEY(pkey.get(), private_key_.get());

  uint8 *public_key { public_key_x509_ };
  i2d_PUBKEY(pkey.get(), &public_key);
  public_key_.set(reinterpret_cast<char *>(public_key_x509_),
  	  kP256PublicKeyX509Bytes);

  return public_key_;
}

// static
bool P256KeyExchangeX509::GetPublicValueFromX509(
    const base::StringPiece& peer_public_x509, std::string& out_public_value) {

  if (peer_public_x509.size() != kP256PublicKeyX509Bytes) {
    DVLOG(1) << "X.509 public key in wrong size.";
    return false;
  }

  const unsigned char *public_key_data {
    reinterpret_cast<const unsigned char *>(peer_public_x509.data()) };

  crypto::ScopedEVP_PKEY pkey {
    d2i_PUBKEY(nullptr, &public_key_data, peer_public_x509.size()) };
  if (pkey.get() == nullptr) {
    DVLOG(1) << "Unable to convert public key.";
    return false;
  }

  const EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey.get());

  uint8 public_key[kUncompressedP256PointBytes];
  if (EC_POINT_point2oct(EC_KEY_get0_group(ec_key),
                         EC_KEY_get0_public_key(ec_key),
                         POINT_CONVERSION_UNCOMPRESSED, public_key,
                         sizeof(public_key), nullptr) != sizeof(public_key)) {
    DVLOG(1) << "Can't get public key.";
    return false;
  }

  out_public_value.assign(reinterpret_cast<const char*>(public_key),
                          sizeof(public_key));

  return true;
}

}  // namespace crypto
