#include "base/strings/string_util.h"
#include "base/base64.h"
#include "crypto/random.h"
#include "crypto/sha2.h"
#include "net/quic/crypto/p256_key_exchange.h"
#include "crypto/rijndael.h"

#include "net/udp/udp_client_socket.h"
#include "net/base/test_completion_callback.h"
#include "crypto/p256_key_exchange_x509.h"
#include "crypto/just_fast_keying.h"

using namespace net;

#include <iostream>
#include <iomanip>
#include <base/rand_util.h>

// darknet handshake test. Pick a nonce, ECDH keypair, iv and padding length

const size_t kBlockSize = 32;

const char i1_identity[] = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const char my_identity[] = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";

const size_t kMaxFreenetPacketSize = 1232;
const size_t kMinPaddingLength = 100;

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

extern "C" {
int i2d_PUBKEY(EVP_PKEY *a, unsigned char **pp);
int X509_PUBKEY_set(X509_PUBKEY **x, EVP_PKEY *pkey);
EVP_PKEY *X509_PUBKEY_get(X509_PUBKEY *key);
}

CompletionCallback cc;

// Loop until |msg| has been written to the socket or until an
// error occurs.
int WriteSocket(UDPClientSocket* socket, std::string msg) {
  int length = static_cast<int>(msg.length());
  scoped_refptr<StringIOBuffer> io_buffer(new StringIOBuffer(msg));
  scoped_refptr<DrainableIOBuffer> buffer(
    new DrainableIOBuffer(io_buffer.get(), length));

  int bytes_sent = 0;
  while (buffer->BytesRemaining()) {
    int rv = socket->Write(
        buffer.get(), buffer->BytesRemaining(), cc);
    if (rv == ERR_IO_PENDING)
      rv = 0; //callback.WaitForResult();
    if (rv <= 0)
      return bytes_sent > 0 ? bytes_sent : rv;
    bytes_sent += rv;
    buffer->DidConsume(rv);
  }
  return bytes_sent;
}

// Creates and address from an ip/port and returns it in |address|.
void CreateUDPAddress(std::string ip_str, uint16 port, IPEndPoint* address) {
  IPAddressNumber ip_number;
  bool rv = ParseIPLiteralToNumber(ip_str, &ip_number);
  if (!rv)
    return;
  *address = IPEndPoint(ip_number, port);
}


int main() {
  crypto::JustFastKeying jfk1;

  // payload is ready
  std::string message1(jfk1);

  std::cout << "message1: " << std::endl;
  std::cout << hexdump(message1);

  // get a 256-bit IV
  crypto::Nonce iv(kBlockSize);

  // sha256 of payload
  auto hash(crypto::SHA256HashString(message1));

  // calculate final length
  size_t prePaddingLength(kBlockSize + hash.length() + 2 + message1.length());
  auto paddingLength(base::RandUint64() % std::min(kMinPaddingLength, 
    kMaxFreenetPacketSize - prePaddingLength));

  // create simmetric key
  std::string i1_id;
  base::Base64Decode(i1_identity, &i1_id);
  auto hash_i1(crypto::SHA256HashString(i1_id));
  
  std::string my_id;
  base::Base64Decode(my_identity, &my_id);
  auto my_hash(crypto::SHA256HashString(crypto::SHA256HashString(my_id)));
  
  char out_key[kBlockSize];
  for (size_t i=0; i<hash_i1.length(); i++)
    out_key[i] = hash_i1[i] ^ my_hash[i];
  
  std::string data(iv);          // first, initial vector
  crypto::Rijndael rijndael(out_key, static_cast<std::string>(iv));
  rijndael.Encrypt(hash, data);  // encrypt hash

  // encrypt length
  int length = message1.length();
  char L[] = { (uint8_t)length>>8, (uint8_t)(0xff & length) };
  rijndael.Encrypt(base::StringPiece(L, sizeof(L)), data);
  
  // encrypt payload
  rijndael.Encrypt(message1, data);

  std::string rnd_bytes;  
  crypto::RandBytes(WriteInto(&rnd_bytes, paddingLength+1), paddingLength);
  data.append(rnd_bytes);
  
  std::cout << "data: " << std::endl;
  std::cout << hexdump(data);

  // Setup the client.
  IPEndPoint server_address;
  CreateUDPAddress("127.0.0.1", kPort, &server_address);
  scoped_ptr<UDPClientSocket> client(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND,
                          RandIntCallback() /*,
                          nullptr,
                          NetLog::Source()*/));
  client->Connect(server_address);

  // Client sends to the server.
  return WriteSocket(client.get(), data);
}
