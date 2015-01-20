// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/crypto/p256_key_exchange.h"

#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>

#include "base/logging.h"

using base::StringPiece;
using std::string;

namespace net {

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

QuicTag P256KeyExchange::tag() const { return kP256; }

}  // namespace net
