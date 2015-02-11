// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange.h"

#include <string>
#include <openssl/x509.h>
#include "base/logging.h"

using base::StringPiece;
using std::string;

namespace crypto {

P256KeyExchange::P256KeyExchange()
    : private_key_(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) {
  DCHECK(private_key_.get());

  // Generate a new random private key.
  auto gen_result(EC_KEY_generate_key(private_key_.get()));
  DCHECK(gen_result);

  // Get the public key from the private one.
  auto size_public(
    EC_POINT_point2oct(EC_KEY_get0_group(private_key_.get()),
                       EC_KEY_get0_public_key(private_key_.get()),
                       POINT_CONVERSION_UNCOMPRESSED, public_key_,
                       sizeof(public_key_), nullptr));
  DCHECK_EQ(size_public, sizeof(public_key_));
}

P256KeyExchange::~P256KeyExchange() {
}

bool P256KeyExchange::CalculateSharedKey(const StringPiece& peer_public_value,
                                         string* out_result) const {
  if (peer_public_value.size() != kUncompressedP256PointBytes) {
    DVLOG(1) << "Peer public value is invalid";
    return false;
  }

  crypto::ScopedOpenSSL<EC_POINT, EC_POINT_free>::Type point(
      EC_POINT_new(EC_KEY_get0_group(private_key_.get())));
  if (!point.get() ||
      !EC_POINT_oct2point( /* also test if point is on curve */
          EC_KEY_get0_group(private_key_.get()),
          point.get(),
          reinterpret_cast<const uint8*>(peer_public_value.data()),
          peer_public_value.size(), nullptr)) {
    DVLOG(1) << "Can't convert peer public value to curve point.";
    return false;
  }

  uint8 result[kP256FieldBytes];
  if (ECDH_compute_key(result, sizeof(result), point.get(), private_key_.get(),
                       nullptr) != sizeof(result)) {
    DVLOG(1) << "Can't compute ECDH shared key.";
    return false;
  }

  out_result->assign(reinterpret_cast<char*>(result), sizeof(result));
  return true;
}

StringPiece P256KeyExchange::public_value() const {
  return StringPiece(reinterpret_cast<const char*>(public_key_),
                     sizeof(public_key_));
}

base::StringPiece P256KeyExchange::GetX509Public() const {
  if (!public_key_x509_str_.empty()) return public_key_x509_str_;

  // We get the public in X.509 format from the private key
  crypto::ScopedEVP_PKEY pkey { EVP_PKEY_new() };
  EVP_PKEY_set1_EC_KEY(pkey.get(), private_key_.get());

  uint8 *public_key { public_key_x509_ };
  i2d_PUBKEY(pkey.get(), &public_key);
  public_key_x509_str_.set(reinterpret_cast<char *>(public_key_x509_),
      kP256PublicKeyX509Bytes);

  return public_key_x509_str_;
}

// static
bool P256KeyExchange::GetPublicValueFromX509(
    const base::StringPiece& peer_public_x509,
    std::string *out_public_value) {

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

  out_public_value->assign(reinterpret_cast<const char*>(public_key),
                           sizeof(public_key));

  return true;
}

}  // namespace crypto
