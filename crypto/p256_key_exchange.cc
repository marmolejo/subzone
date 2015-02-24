// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/p256_key_exchange.h"

#include <openssl/x509.h>
#include <string>
#include "base/logging.h"
#include "crypto/sha2.h"

using base::StringPiece;
using std::string;

namespace crypto {
namespace {

bool ProcessPublicKey(
  const base::StringPiece& public_key,
  crypto::ScopedEVP_PKEY *pkey) {
  DCHECK(pkey);

  if (public_key.size() != P256KeyExchange::kP256PublicKeyX509Bytes) {
    DVLOG(1) << "Wrong size for X.509 public key.";
    return false;
  }

  const unsigned char *public_key_data {
    reinterpret_cast<const unsigned char *>(public_key.data()) };

  // d2i_PUBKEY converts it back from network format
  pkey->reset(d2i_PUBKEY(nullptr, &public_key_data, public_key.size()));
  if (pkey->get() == nullptr) {
    DVLOG(1) << "Unable to convert public key.";
    return false;
  }
  return true;
}

}  // namespace

P256KeyExchange::P256KeyExchange() {
}

P256KeyExchange::~P256KeyExchange() {
}

bool P256KeyExchange::Init() {
  private_key_.reset(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
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

  return true;
}

bool P256KeyExchange::Init(const base::StringPiece& private_key) {
  const uint8_t *private_key_data {
    reinterpret_cast<const uint8_t *>(private_key.data()) };

  // Parse DER formatted private key. This will create an EVP_KEY structure
  // in the heap, therefore we are responsible for freeing the memory after use.
  // Ideal for a scoped_ptr.
  crypto::ScopedEVP_PKEY evp_key {
    d2i_AutoPrivateKey(nullptr, &private_key_data, private_key.size()) };

  if (evp_key.get() == nullptr) {
    DVLOG(1) << "Error parsing private key in DER format.";
    return false;
  }

  // Get the EC key from the EVP
  EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(evp_key.get());
  if (eckey == nullptr) {
    DVLOG(1) << "Private key is not an EC type key.";
    return false;
  }

  // As the EVP object will be deleted after returning from this function, we
  // must copy the EC field to this object.
  private_key_.reset(EC_KEY_dup(eckey));
  DCHECK(private_key_.get());

  // Get the public key from the private one.
  auto size_public(
    EC_POINT_point2oct(EC_KEY_get0_group(private_key_.get()),
                       EC_KEY_get0_public_key(private_key_.get()),
                       POINT_CONVERSION_UNCOMPRESSED, public_key_,
                       sizeof(public_key_), nullptr));
  DCHECK_EQ(size_public, sizeof(public_key_));

  return true;
}

bool P256KeyExchange::CalculateSharedKey(const StringPiece& peer_public_value,
                                         string* out_result) const {
  if (peer_public_value.size() != kUncompressedP256PointBytes) {
    DVLOG(1) << "Peer public value is invalid";
    return false;
  }

  // Get the point in the EC from our private key and the peer's public.
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

  // Get the public in X.509 format from the private key
  crypto::ScopedEVP_PKEY pkey { EVP_PKEY_new() };
  EVP_PKEY_set1_EC_KEY(pkey.get(), private_key_.get());

  // i2d_PUBKEY does this transform to network format.
  uint8 *public_key { public_key_x509_ };
  i2d_PUBKEY(pkey.get(), &public_key);
  public_key_x509_str_.set(reinterpret_cast<char *>(public_key_x509_),
      kP256PublicKeyX509Bytes);

  return public_key_x509_str_;
}

base::StringPiece P256KeyExchange::GetSignature() const {
  if (!signature_str_.empty()) return signature_str_;

  // Compute sha256 digest from the public x509 value
  std::string hash(crypto::SHA256HashString(GetX509Public()));

  // Get the heap-allocated signature object
  crypto::ScopedECDSA_SIG sig {
    ECDSA_do_sign(reinterpret_cast<const uint8_t *>(&hash[0]),
                  SHA256_DIGEST_LENGTH, private_key_.get()) };

  // Convert it to DER format for export
  uint8 *signature { signature_ };
  i2d_ECDSA_SIG(sig.get(), &signature);
  signature_str_.set(reinterpret_cast<char *>(signature_), kSignatureBytes);

  return signature_str_;
}

// static
bool P256KeyExchange::VerifySignature(
  const base::StringPiece& peer_public_x509,
  const base::StringPiece& signature) {
  // Compute sha256 digest from the public x509 value
  std::string hash(crypto::SHA256HashString(peer_public_x509));

  // Convert signature in DER format to internal SSL for later processing.
  const unsigned char *signature_data {
    reinterpret_cast<const unsigned char *>(signature.data()) };
  crypto::ScopedECDSA_SIG sig {
    d2i_ECDSA_SIG(nullptr, &signature_data, signature.size()) };
  if (sig.get() == nullptr) {
    DVLOG(1) << "Unable to convert signature.";
    return false;
  }

  // Process public key takes the public key passed as parameter in DER format
  // and transforms it in an internal format, necessary for later processing.
  crypto::ScopedEVP_PKEY pkey;
  if (!ProcessPublicKey(peer_public_x509, &pkey)) {
    DVLOG(1) << "Can't process public key.";
    return false;
  }

  // From the EVP_PKEY structure, take the EC_KEY field, which is the one we are
  // interested in.
  EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey.get());

  // Call verificaion on the signature converted to internal format. If the
  // signature matches, it will return true.
  if (ECDSA_do_verify(reinterpret_cast<const uint8_t *>(&hash[0]),
                      SHA256_DIGEST_LENGTH, sig.get(), ec_key) != 1) {
    DVLOG(1) << "Can't verify public key.";
    return false;
  }

  return true;
}

// static
bool P256KeyExchange::GetPublicValueFromX509(
    const base::StringPiece& peer_public_x509,
    std::string *out_public_value) {

  crypto::ScopedEVP_PKEY pkey;
  if (!ProcessPublicKey(peer_public_x509, &pkey)) {
    DVLOG(1) << "Can't process public key.";
    return false;
  }

  const EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(pkey.get());

  // With this we have the public key in a 'workable' format.
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
