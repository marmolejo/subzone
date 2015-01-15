// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debug/hexdump.h"
#include <sstream>
#include <iomanip>

namespace base {
namespace debug {

Hexdump::Hexdump(base::StringPiece sp)
  : contents_(sp.as_string()) {
}

std::ostream& operator<< (std::ostream& stream, const Hexdump& hd) {
  std::istringstream is(hd.contents_);
  unsigned long address = 0;

  stream << std::hex << std::setfill('0');
  while( is.good() ) {
    int nread;
    char buf[16];

    for( nread = 0; nread < 16 && is.get(buf[nread]); nread++ );
    if( nread == 0 ) break;

    // Show the address
    stream << std::setw(8) << address;

    // Show the hex codes
    for( int i = 0; i < 16; i++ )
    {
      if( i % 8 == 0 ) stream << ' ';
      if( i < nread )
        stream << ' ' << std::setw(2) << std::hex << (uint16_t)(buf[i] & 0x00ff);
      else
        stream << "   ";
    }

    // Show printable characters
    stream << "  ";
    for( int i = 0; i < nread; i++)
    {
      if( buf[i] < 32 ) stream << '.';
      else stream << buf[i];
    }

    stream << "\n";
    address += 16;
  }
  return stream;
}

}  // namespace debug
}  // namespace base
