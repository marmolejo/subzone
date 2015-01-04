#include "net/udp/udp_client_socket.h"

#include "net/base/test_completion_callback.h"

using namespace net;

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
  const uint16 kPort = 6991;
  std::string simple_message("hello world!");

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
  return WriteSocket(client.get(), simple_message);
}
