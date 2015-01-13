#include "base/strings/string_util.h"
#include "base/base64.h"
#include "crypto/random.h"
#include "crypto/sha2.h"
#include "net/quic/crypto/p256_key_exchange.h"
#include "crypto/rijndael.h"

#include "net/udp/udp_client_socket.h"
#include "net/base/test_completion_callback.h"
#include "net/p256_key_exchange_x509.h"

using namespace net;

#include <iostream>
#include <iomanip>
#include <base/rand_util.h>

// darknet handshake test. Pick a nonce, ECDH keypair, iv and padding length

const size_t kBlockSize = 32;
const size_t kNonceLength = 16;

const uint8_t kVersion = 1;
const uint8_t kNegType = 9;
const uint8_t kPhase   = 0;

const char i1_identity[] = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const char my_identity[] = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";

const size_t kMaxFreenetPacketSize = 1232;
const size_t kMinPaddingLength = 100;

const uint16 kPort = 6991;

std::string hexdump(std::string &in)
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
  // Get a 128-bit nonce hash
  std::string nonce;
  crypto::RandBytes(WriteInto(&nonce, kNonceLength + 1), kNonceLength);
  std::string hash_nonce(crypto::SHA256HashString(nonce));
  std::string message1(hash_nonce);

  net::P256KeyExchangeX509 ecdhe_key;
  ecdhe_key.GetX509Public().AppendToString(&message1);

  // Add version, negType and phase
  const char pr[] = { kVersion, kNegType, kPhase };
  std::string preface(pr, 3);
  message1.insert(0, preface);

  // payload is ready
  std::cout << "message1: " << std::endl;
  std::cout << hexdump(message1);

  // get a 256-bit IV
  std::string iv;
  crypto::RandBytes(WriteInto(&iv, kBlockSize + 1), kBlockSize);

  // sha256 of payload
  auto hash(crypto::SHA256HashString(message1));

  // calculate final length
  size_t prePaddingLength(iv.length() + hash.length() + 2 + message1.length());
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
  for (int i=0; i<hash_i1.length(); i++) out_key[i] = hash_i1[i] ^ my_hash[i];
  
  crypto::Rijndael rijndael;
  rijndael.MakeKey(out_key, iv.c_str(), kBlockSize, kBlockSize);
  
  // first, initial vector
  std::string data(iv);
  
  // encrypt hash
  char out[kBlockSize];
  bzero(out, kBlockSize);
  rijndael.Encrypt(hash.c_str(), out, kBlockSize, rijndael.CFB);
  data.append(out, kBlockSize);
  
  // encrypt length
  bzero(out,kBlockSize);
  int length = message1.length();
  uint8_t L = (uint8_t)length>>8; 
  rijndael.Encrypt(reinterpret_cast<const char *>(&L), out, 1, rijndael.CFB);
  data.append(out, 1);
  
  out[0] = 0;
  L = (uint8_t)(0xff & length);
  rijndael.Encrypt(reinterpret_cast<const char *>(&L), out, 1, rijndael.CFB);
  data.append(out, 1);
  
  // encrypt payload
  char payenc[length];
  rijndael.Encrypt(message1.c_str(), payenc, length, rijndael.CFB);
  data.append(payenc, length);

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
