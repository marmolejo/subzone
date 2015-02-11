// Copyright 2015 The Subzone Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "debug/hexdump.h"
#include <sstream>
#include <iomanip>
#include <iostream>

void hexdump(base::StringPiece label, base::StringPiece sp) {
  std::cout << label << ":" << std::endl;

  std::istringstream is(sp.as_string());
  unsigned long address = 0;

  std::cout << std::hex << std::setfill('0');
  while( is.good() ) {
    int nread;
    char buf[16];

    for( nread = 0; nread < 16 && is.get(buf[nread]); nread++ );
    if( nread == 0 ) break;

    // Show the address
    std::cout << std::setw(8) << address;

    // Show the hex codes
    for( int i = 0; i < 16; i++ )
    {
      if( i % 8 == 0 ) std::cout << ' ';
      if( i < nread )
        std::cout << ' ' << std::setw(2) << std::hex << (uint16_t)(buf[i] & 0x00ff);
      else
        std::cout << "   ";
    }

    // Show printable characters
    std::cout << "  ";
    for( int i = 0; i < nread; i++)
    {
      if( buf[i] < 32 ) std::cout << '.';
      else std::cout << buf[i];
    }

    std::cout << "\n";
    address += 16;
  }

}
