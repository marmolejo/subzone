// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef NET_DARKNET_AUTH_H_
#define NET_DARKNET_AUTH_H_

#include "base/strings/string_piece.h"
#include "net/udp/udp_client_socket.h"
#include "crypto/handshake.h"

namespace net {

class DarknetAuth {
 public:
  DarknetAuth(base::StringPiece my_id, base::StringPiece peer_id,
              base::StringPiece ip_str, uint16 port);
  ~DarknetAuth();

  int SendJFK1();

 private:
  // Creates and address from an ip/port and returns it in |address|.
  static void CreateUDPAddress(base::StringPiece ip_str, uint16 port,
                               IPEndPoint* address);

  crypto::Handshake hs_;
  UDPClientSocket client_;
  CompletionCallback cc_;
};

}  // namespace net

#endif  // NET_DARKNET_AUTH_H_
