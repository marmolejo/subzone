// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DARKNET_AUTH_H_
#define NET_DARKNET_AUTH_H_

#include "base/strings/string_piece.h"
#include "crypto/handshake.h"
#include "net/udp/udp_client_socket.h"

namespace net {

// DarknetAuth sends the first auth packet for a Darknet connection to a
// specified IP address. This includes sending the handshake.
class DarknetAuth {
 public:
  // To build the object we need the identities of the two peers, specified in
  // |my_id| and |peer_id| and the IP address in |ip_str| and |port| to send
  // the UDP packet.
  DarknetAuth(base::StringPiece my_id, base::StringPiece peer_id,
              base::StringPiece ip_str, uint16 port);
  ~DarknetAuth();

  // The packet is actually sent by calling to SendJFK1()
  int SendJFK1();

 private:
  // Creates and address from an ip/port and returns it in |address|.
  static void CreateUDPAddress(base::StringPiece ip_str, uint16 port,
                               IPEndPoint* address);

  // The handshake object containing the IV, hash and payload
  crypto::Handshake hs_;

  UDPClientSocket client_;
  CompletionCallback cc_;  // This should fire up when the message is sent.
};

}  // namespace net

#endif  // NET_DARKNET_AUTH_H_
