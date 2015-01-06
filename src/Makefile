CXX	:= c++
FLAGS := -O3 -flto -fno-exceptions -fno-rtti -Wall
CXXFLAGS = -std=c++14 $(FLAGS)
CFLAGS = $(FLAGS)
LDFLAGS  := -flto
INCLUDES := -Ichrome -Ichrome/out/Default/gen
DEFINES  := -DUSE_OPENSSL -DNDEBUG
LIBS     := -lpthread -levent -licuuc
OBJECTS := \
chrome/base/base64.o \
chrome/base/callback_internal.o \
chrome/base/files/file_util_posix.o \
chrome/base/lazy_instance.o \
chrome/base/memory/ref_counted.o \
chrome/base/memory/weak_ptr.o \
chrome/base/message_loop/message_pump_libevent.o \
chrome/base/rand_util_posix.o \
chrome/crypto/random.o \
chrome/crypto/secure_hash_default.o \
chrome/crypto/sha2.o \
chrome/crypto/third_party/nss/sha512.o \
chrome/net/base/io_buffer.o \
chrome/net/base/ip_endpoint.o \
chrome/net/base/net_util.o \
chrome/net/quic/crypto/p256_key_exchange_openssl.o \
chrome/net/socket/socket_descriptor.o \
chrome/net/udp/udp_client_socket.o \
chrome/net/udp/udp_socket_libevent.o \
chrome/third_party/modp_b64/modp_b64.o \
chrome/url/url_canon_internal.o \
chrome/url/url_canon_ip.o \
crypto/rijndael.o \
crypto_test.o \
/home/zeus/src/boringssl/out/crypto/libcrypto.a

crypto_test: $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

%.o: %.c
	clang $(DEFINES) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc
	$(CXX) $(DEFINES) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f crypto_test *.o
	find . -name *.o | xargs rm
