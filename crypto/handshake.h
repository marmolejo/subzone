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

  // BuildKeys gets the simmetric Rijndael key that is derived from the
  // identities of the two peers. There are two simmetric keys, outgoing key and
  // incoming key.
  void BuildKeys(base::StringPiece i0, base::StringPiece i1);

  // NextPhase checks in which phase in the negotiation we are, taking an
  // incoming message |in|, checking the correct length and hash, then building
  // the next message in |out|. If incoming message has some error, according
  // to the current phase, return false.
  bool NextPhase(base::StringPiece in, std::string *out);

 private:
  FRIEND_TEST_ALL_PREFIXES(Handshake, BuildKeys);
  FRIEND_TEST_ALL_PREFIXES(Handshake, EncryptDecrypt);

  // BuildAuthPacket encrypts, hashes and builds the final auth packet that will
  // be sent through the net. It gets the jfk_ member as string which is the
  // payload and write the final packet to |out|.
  void BuildAuthPacket(std::string *out);

  // TryProcessAuth does the inverse as BuildAuthPacket. In this case, it gets
  // an encrypted packet in |in| and tries to decrypt it. It may happen that
  // this is not an auth packet or it's malformed, in this case, the return
  // value is false. The output decrypted packet is written to |out|.
  bool TryProcessAuth(base::StringPiece in, std::string *out);

  enum {
    kBlockSize = 32,  // 256-bit blocks, for the IV

    // These two values are taken from the reference daemon
    kMaxFreenetPacketSize = 1232,
    kMinPaddingLength = 100,
  };

  // This is the "content" of the message, the public ECDSA key
  std::unique_ptr<Jfk> jfk_;

  // Depending if we are initiators or not, it is phase 0 or 1
  unsigned phase_;

  // Incoming and outgoing cipher keys
  std::string in_key_;
  std::string out_key_;
};

}  // namespace crypto

#endif  // CRYPTO_HANDSHAKE_H_
