// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "crypto/handshake.h"

#include "base/base64.h"
#include "base/rand_util.h"
#include "base/strings/string_util.h"
#include "crypto/jfk1.h"
#include "crypto/jfk2.h"
#include "crypto/nonce.h"
#include "crypto/random.h"
#include "crypto/sha2.h"

namespace crypto {

Handshake::Handshake(base::StringPiece i0, base::StringPiece i1,
                     bool initiator)
    : jfk_(initiator ?
           static_cast<std::unique_ptr<Jfk>>(std::make_unique<Jfk1>())
         : static_cast<std::unique_ptr<Jfk>>(std::make_unique<Jfk2>())),
      phase_(initiator ? 0 : 1) {
  DCHECK_EQ(i0.length(), 43);  // base64 encoding of an Identity
  DCHECK_EQ(i0.length(), 43);

  // Build incoming and outgoing keys
  BuildKeys(i0, i1);
}

// This method builds both the symmetric outgoing and incoming Rijndael keys,
// incoming and outgoing keys are different. Outgoing key is created by XORing
// the double hash of the peer's identity together with the single hash of our
// identity. Incoming key comes from the XOR of the double hash of our identity
// together with the single hash of theirs.
void Handshake::BuildKeys(base::StringPiece i0, base::StringPiece i1) {
  // Calculate first both hashes.
  std::string i0_id;
  base::Base64Decode(i0, &i0_id);
  auto i0_hash(crypto::SHA256HashString(i0_id));
  auto i0_hash_hash(crypto::SHA256HashString(i0_hash));

  std::string i1_id;
  base::Base64Decode(i1, &i1_id);
  auto i1_hash(crypto::SHA256HashString(i1_id));
  auto i1_hash_hash(crypto::SHA256HashString(i1_hash));

  // We XOR together the 2 hashes for the incoming and outgoing key creation.
  out_key_.resize(kBlockSize);
  in_key_.resize(kBlockSize);
  for (size_t i=0; i < i1_hash.length(); ++i) {
    out_key_[i] = i1_hash[i] ^ i0_hash_hash[i];
    in_key_[i] = i0_hash[i] ^ i1_hash_hash[i];
  }
}

void Handshake::BuildAuthPacket(std::string *out) {
  DCHECK(out);

  Nonce iv(kBlockSize);
  Rijndael rijndael(in_key_, static_cast<std::string>(iv));

  // First the initial vector.
  out->append(iv);

  // Then we encrypt the SHA-256 hash of the payload
  rijndael.Encrypt(crypto::SHA256HashString(static_cast<std::string>(*jfk_)),
                   out);

  // Encrypt length
  int length = jfk_->Length();
  char L[] = { static_cast<char>(length>>8),
               static_cast<char>(0xff & length) };
  rijndael.Encrypt(base::StringPiece(L, sizeof(L)), out);

  // Encrypt payload
  rijndael.Encrypt(static_cast<std::string>(*jfk_), out);

  // Add some extra random bytes.
  auto pre_padding_length(2 * kBlockSize + 2 + length);

  // The payload cannot be larger than the MaxFreenetPacketSize, otherwise it
  // won't fit.
  DCHECK_GE(kMaxFreenetPacketSize, pre_padding_length);

  // Will be padding at max 100 bytes extra, it can be less if the package is
  // big enough.
  auto padding_length(base::RandUint64() % std::min(
    static_cast<int>(kMinPaddingLength),
    kMaxFreenetPacketSize - pre_padding_length));

  // padding_length may be zero. In this case, we don't call WriteInto because
  // it would give an error.
  if (padding_length) {
    std::string rnd_bytes;
    crypto::RandBytes(WriteInto(&rnd_bytes, padding_length+1),
                      padding_length);
    out->append(rnd_bytes);
  }
}

bool Handshake::TryProcessAuth(base::StringPiece in, std::string *out) {
  DCHECK(out);

  // Packet has to have at least space for the IV, the SHA-256 digest of the
  // message, length (2 bytes) and some bytes for the payload (2 at least)
  if (in.length() < 2 * kBlockSize + 4) {
    DVLOG(1) << "Packet too short.";
    return false;
  }

  // We create a new CFB Rijndael 256 cipher taking as IV the first 256 bits.
  Rijndael rijndael(in_key_, in.substr(0, kBlockSize));

  // Following the IV it's the SHA-256 hash of the message, we take it for later
  // verification.
  std::string hash;
  rijndael.Decrypt(in.substr(kBlockSize, kBlockSize), &hash);

  // 2 bytes containing the payload length.
  std::string length_str;
  rijndael.Decrypt(in.substr(kBlockSize * 2, 2), &length_str);

  // Process length. First byte is the most significant one.
  int length = { static_cast<uint8_t>(length_str[0])*256 +
                 static_cast<uint8_t>(length_str[1]) };

  // Check length. We should have at least *length* bytes available remaining.
  // It could be more, but these are random padding bytes.
  if (length > in.length() - (kBlockSize * 2 + 2)) {
    DVLOG(1) << "Invalid data length " << length;
    return false;
  }

  // Get payload. We start decrypting after the IV, hash and length, and take
  // exactly the number of bytes specified in *length*. We save it on a
  // temporary variable as we don't know if the hash will match. If it doesn't
  // match, we should return false and don't modify the output parameter |out|.
  std::string payload;
  rijndael.Decrypt(in.substr(kBlockSize * 2 + 2, length), &payload);

  // Now that we have the payload, we can hash it to check if it matches with
  // the hash in the header that we took previously.
  if (hash.compare(crypto::SHA256HashString(payload))) {
    DVLOG(1) << "Incorrect hash in TryProcessAuth";
    return false;
  }

  // Now we are sure that the payload is what it should be, so we modify the
  // output parameter copying the payload string.
  *out = payload;

  return true;
}

bool Handshake::NextPhase(base::StringPiece in, std::string *out) {
  DCHECK(out);

  // First decrypt the message
  if (phase_) {  // we are in a phase > 0, so we have to process a incoming
                 // message.
    std::string decrypted;
    if (!TryProcessAuth(in, &decrypted)) {
      DVLOG(1) << "Error decrypting malformed message in phase " << phase_;
      return false;
    }

    // Initialize properly the current phase we are, with the incoming message.
    // If incoming message is malformed, return false.
    if (!jfk_->Init(decrypted)) {
      DVLOG(1) << "Wrong format for incoming message in phase " << phase_;
      return false;
    }
  }

  // Once the payload is done for the next message, just build the auth packet
  // by encrypting the payload and adding the hash.
  BuildAuthPacket(out);

  return true;
}

}  // namespace crypto
