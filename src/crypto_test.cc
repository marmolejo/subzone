#include "base/strings/string_util.h"
#include "base/base64.h"
#include "crypto/random.h"
#include "crypto/sha2.h"
#include "net/quic/crypto/p256_key_exchange.h"
#include "crypto/rijndael.h"

#include "net/udp/udp_client_socket.h"
#include "net/base/test_completion_callback.h"

using namespace net;

#include <iostream>
#include <iomanip>
#include <base/rand_util.h>

// darknet handshake test. Pick a nonce, ECDH keypair, iv and padding length

const size_t kBlockSize = 32;
const size_t kKeyLength = 32;
const size_t kNonceLength = 16;
const size_t kECPrivateKeyLength = 121;

const char i1_identity[] = "gAXIdY1ZIY5imCwcISPDmkUCfEf0iT463+k2PkAh8Cw";
const char my_identity[] = "tMh1zG3Vy+c+dfeGqPRn+Df9Ich0K89U6SiAci2hgPk";

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

// Loop until |msg| has been written to the socket or until an
// error occurs.
int WriteSocket(UDPClientSocket* socket, std::string msg) {
  TestCompletionCallback callback;

  int length = static_cast<int>(msg.length());
  scoped_refptr<StringIOBuffer> io_buffer(new StringIOBuffer(msg));
  scoped_refptr<DrainableIOBuffer> buffer(
    new DrainableIOBuffer(io_buffer.get(), length));

  int bytes_sent = 0;
  while (buffer->BytesRemaining()) {
    int rv = socket->Write(
        buffer.get(), buffer->BytesRemaining(), callback.callback());
    if (rv == ERR_IO_PENDING)
      rv = callback.WaitForResult();
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

  // Create a ECDH secp256r1 keypair
  //base::StringPiece ecpriv64(kECPrivateKey64);
  std::string key(net::P256KeyExchange::NewPrivateKey());
  const uint8* keyp = reinterpret_cast<const uint8*>(key.data());
  crypto::ScopedEC_KEY private_key(d2i_ECPrivateKey(nullptr, &keyp,
                                                    key.size()));
  if (!private_key.get() || !EC_KEY_check_key(private_key.get())) {
    DVLOG(1) << "Private key is invalid.";
    return 0;
  }

  EVP_PKEY pkey;
  EVP_PKEY_set1_EC_KEY(&pkey, private_key.get());
  unsigned char *d = (unsigned char*) malloc(91);
  unsigned char *p = d;
  i2d_PUBKEY(&pkey, &p);

  //base::Base64Decode(ecpriv64, &node_private);
  //scoped_ptr<net::P256KeyExchange> node(net::P256KeyExchange::New(node_private));
  message1.append(reinterpret_cast<const char *>(d), 91);

  // Add version, negType and phase
  const char pr[] = { 1, 9, 0 };
  std::string preface(pr, 3);
  message1.insert(0, preface);

  std::cout << "message1: " << std::endl;
  std::cout << hexdump(message1);

  // 256-bit IV
  std::string iv;
  crypto::RandBytes(WriteInto(&iv, kBlockSize + 1), kBlockSize);

  // sha256 of payload
  auto hash(crypto::SHA256HashString(message1));
  auto hash_iv(crypto::SHA256HashString(iv));
  size_t prePaddingLength(iv.length() + hash_iv.length() + 2 + message1.length());
  const size_t kMaxPacketSize = 1232;
  auto paddingLength(base::RandUint64() % std::min(100UL, kMaxPacketSize - prePaddingLength));

  // create simmetric key
  std::string i1_id;
  base::Base64Decode(i1_identity, &i1_id);
  auto hash_i1(crypto::SHA256HashString(i1_id));
  
  std::string my_id;
  base::Base64Decode(my_identity, &my_id);
  auto my_hash(crypto::SHA256HashString(crypto::SHA256HashString(my_id)));
  
  char out_key[32];
  for (int i=0; i<hash_i1.length(); i++) out_key[i] = hash_i1[i] ^ my_hash[i];
  
  // encrypt hash
  crypto::Rijndael rijndael;
  rijndael.MakeKey(out_key, iv.c_str(), 32, 32);
  
  std::string data(iv);
  
  char out[32];
  bzero(out, 32);
  rijndael.Encrypt(hash.c_str(), out, 32, rijndael.CFB);
  data.append(out, 32);
  
  // encrypt length
  bzero(out,32);
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

  const uint16 kPort = 6991;

  // Setup the client.
  IPEndPoint server_address;
  CreateUDPAddress("127.0.0.1", kPort, &server_address);
  scoped_ptr<UDPClientSocket> client(
      new UDPClientSocket(DatagramSocket::DEFAULT_BIND,
                          RandIntCallback(),
                          nullptr,
                          NetLog::Source()));
  client->Connect(server_address);

  // Client sends to the server.
  return WriteSocket(client.get(), data);
}