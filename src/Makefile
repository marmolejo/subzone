CXX	:= c++
FLAGS := -g3 -O0 -flto -fno-exceptions -fno-rtti -Wall -Wsign-compare -Wendif-labels -Werror -Wno-missing-field-initializers -Wno-unused-parameter -Wno-c++11-narrowing -Wno-char-subscripts -Wno-covered-switch-default -Wno-deprecated-register -Wno-unneeded-internal-declaration -Wno-reserved-user-defined-literal -Wheader-hygiene -Wstring-conversion -Wno-undefined-bool-conversion -Wno-tautological-undefined-compare
CXXFLAGS = -std=c++1z $(FLAGS)
CFLAGS = $(FLAGS)
LDFLAGS  := -flto
INCLUDES := -I../contrib/chrome -I../contrib/chrome/out/Default/gen -I../contrib -I.. -I/home/zeus/src/googletest/include -I/home/zeus/src/googletest
DEFINES  := -DUSE_OPENSSL -DNDEBUG
LIBS     := -lpthread -levent -licuuc
OBJECTS := \
../contrib/chrome/base/base64.o \
../contrib/chrome/base/callback_internal.o \
../contrib/chrome/base/files/file_util_posix.o \
../contrib/chrome/base/lazy_instance.o \
../contrib/chrome/base/memory/ref_counted.o \
../contrib/chrome/base/memory/weak_ptr.o \
../contrib/chrome/base/message_loop/message_pump_libevent.o \
../contrib/chrome/base/rand_util_posix.o \
../contrib/chrome/base/strings/string_piece.o \
../contrib/chrome/crypto/random.o \
../contrib/chrome/crypto/secure_hash_default.o \
../contrib/chrome/crypto/sha2.o \
../contrib/chrome/crypto/third_party/nss/sha512.o \
../contrib/chrome/net/base/io_buffer.o \
../contrib/chrome/net/base/ip_endpoint.o \
../contrib/chrome/net/base/net_util.o \
../contrib/chrome/net/quic/crypto/p256_key_exchange_openssl.o \
../contrib/chrome/net/socket/socket_descriptor.o \
../contrib/chrome/net/udp/udp_client_socket.o \
../contrib/chrome/net/udp/udp_socket_libevent.o \
../contrib/chrome/third_party/modp_b64/modp_b64.o \
../contrib/chrome/url/url_canon_internal.o \
../contrib/chrome/url/url_canon_ip.o \
../contrib/crypto/rijndael.o \
../crypto/p256_key_exchange_x509.o \
../crypto/just_fast_keying.o \
../crypto/nonce.o \
../crypto/handshake.o \
crypto_test.o \
/home/zeus/src/boringssl/out/crypto/libcrypto.a

OBJ_TEST_X509 := ../crypto/p256_key_exchange_x509.o ../crypto/p256_key_exchange_x509_test.o ../contrib/chrome/net/quic/crypto/p256_key_exchange_openssl.o /home/zeus/src/googletest/src/gtest-all.o /home/zeus/src/googletest/src/gtest_main.o ../contrib/chrome/base/strings/string_piece.o /home/zeus/src/boringssl/out/crypto/libcrypto.a

p256_key_exchage_x509_test: $(OBJ_TEST_X509)
	$(CXX) $(LDFLAGS) $(OBJ_TEST_X509) -o $@ $(LIBS)

crypto_test: $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

%.o: %.c
	clang $(DEFINES) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc
	$(CXX) $(DEFINES) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f crypto_test *.o
	find .. -name *.o | xargs rm
