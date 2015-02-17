// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CRYPTO_HANDSHAKE_H_
#define CRYPTO_HANDSHAKE_H_

#include <memory>
#include <string>
#include "base/gtest_prod_util.h"
#include "base/strings/string_piece.h"
#include "crypto/jfk.h"
#include "crypto/rijndael.h"

namespace crypto {

// Handshake creates the header information to send in each authentification.
// To build the key necessary for the communication we need the identities of
// the two peers. These identities are passed to the constructors in the |i0|
// and |i1| parameters.
class Handshake {
 public:
  // We need to know if we are the initiators or the other peer initiated
  // the handshake. |initiator| holds this value.
  Handshake(base::StringPiece i0, base::StringPiece i1, bool initiator);

  // BuildKey gets the simmetric Rijndael key that is derived from the
  // identities of the two peers.
  static std::string BuildKey(base::StringPiece i0, base::StringPiece i1);

  // NextPhase checks in which phase in the negotiation we are, taking an
  // incoming message |in|, checking the correct length and hash, then building
  // the next message in |out|. If incoming message has some error, according
  // with the current phase, return false.
  bool NextPhase(base::StringPiece in, std::string *out);

 private:
  FRIEND_TEST_ALL_PREFIXES(Handshake, EncryptDecrypt);

  // Implicit conversion to std::string will yield the string of bytes of the
  // full packet, including the extra random padding.
  void BuildAuthPacket(std::string *out);

  enum {
    kBlockSize = 32,  // 256-bit blocs, for the IV

    // These two values are taken from the reference daemon
    kMaxFreenetPacketSize = 1232,
    kMinPaddingLength = 100,
  };

  // This is the "content" of the message, the public ECDSA key
  std::unique_ptr<Jfk> jfk_;

  // Depending if we are initiators or not, it is phase 0 or 1
  unsigned phase_;

  Nonce iv_;  // A random nonce
  int pre_padding_length_;
  int padding_length_;

  // Rijndael 256 CFB encryptor
  Rijndael rijndael_;
};

}  // namespace crypto

#endif  // CRYPTO_HANDSHAKE_H_
