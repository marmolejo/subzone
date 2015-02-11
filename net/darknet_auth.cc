// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/darknet_auth.h"

#include <string>
#include "net/base/net_util.h"
#include "net/base/test_completion_callback.h"

namespace net {

DarknetAuth::DarknetAuth(base::StringPiece my_id, base::StringPiece peer_id,
                         base::StringPiece ip_str, uint16 port)
  : hs_(my_id, peer_id),
    client_(DatagramSocket::DEFAULT_BIND, RandIntCallback()) {
  IPEndPoint srv_addr;
  CreateUDPAddress(ip_str, port, &srv_addr);

  client_.Connect(srv_addr);
}

DarknetAuth::~DarknetAuth() {
}

// static
void DarknetAuth::CreateUDPAddress(base::StringPiece ip_str, uint16 port,
                                   IPEndPoint* address) {
  IPAddressNumber ip_number;
  bool rv = ParseIPLiteralToNumber(ip_str.as_string(), &ip_number);
  if (!rv)
    return;
  *address = IPEndPoint(ip_number, port);
}

int DarknetAuth::SendJFK1() {
  // Loop until |hs_| has been written to the socket or until an
  // error occurs.
  std::string msg { static_cast<std::string>(hs_) };
  int length = static_cast<int>(msg.length());

  scoped_refptr<StringIOBuffer> io_buffer(new StringIOBuffer(msg));
  scoped_refptr<DrainableIOBuffer> buffer(
    new DrainableIOBuffer(io_buffer.get(), length));

  int bytes_sent = 0;
  while (buffer->BytesRemaining()) {
    int rv = client_.Write(
        buffer.get(), buffer->BytesRemaining(), cc_);
    if (rv == ERR_IO_PENDING)
      rv = 0;  // callback.WaitForResult();
    if (rv <= 0)
      return bytes_sent > 0 ? bytes_sent : rv;
    bytes_sent += rv;
    buffer->DidConsume(rv);
  }
  return bytes_sent;
}

}  // namespace net
