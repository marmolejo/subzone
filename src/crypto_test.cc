#include "net/darknet_auth.h"

#include <iostream>
#include <iomanip>
#include <base/rand_util.h>

// darknet handshake test. Pick a nonce, ECDH keypair, iv and padding length

const char i1_identity[] = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const char my_identity[] = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";

const uint16 kPort = 6991;

std::string hexdump(const std::string &in)
{
  std::ostringstream os;
  std::istringstream is(in);
  unsigned long address = 0;

  os << std::hex << std::setfill('0');
  while( is.good() ) {
    int nread;
    char buf[16];

    for( nread = 0; nread < 16 && is.get(buf[nread]); nread++ );
    if( nread == 0 ) break;

    // Show the address
    os << std::setw(8) << address;

    // Show the hex codes
    for( int i = 0; i < 16; i++ )
    {
      if( i % 8 == 0 ) os << ' ';
      if( i < nread )
        os << ' ' << std::setw(2) << std::hex << (uint16_t)(buf[i] & 0x00ff);
      else 
        os << "   ";
    }

    // Show printable characters
    os << "  ";
    for( int i = 0; i < nread; i++)
    {
      if( buf[i] < 32 ) os << '.';
      else os << buf[i];
    }

    os << "\n";
    address += 16;
  }
  return os.str();
}

int main() {
  net::DarknetAuth da(my_identity, i1_identity, "127.0.0.1", kPort);

  // Client sends to the server.
  return da.SendJFK1();
}
