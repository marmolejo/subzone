# Chromium LLVM compiler and flags
#
#CXX	:= /home/zeus/src/chromium/src/third_party/llvm-build/Release+Asserts/bin/clang++
#FLAGS := -fno-strict-aliasing -fstack-protector --param=ssp-buffer-size=4 -m64 -march=x86-64 -funwind-tables -fPIC -pipe -pthread -B/home/zeus/src/chromium/src/third_party/binutils/Linux_x64/Release/bin -fcolor-diagnostics -Wall -Wendif-labels -Werror -Wno-missing-field-initializers -Wno-unused-parameter -Wno-c++11-narrowing -Wno-char-subscripts -Wno-covered-switch-default -Wno-deprecated-register -Wno-unneeded-internal-declaration -Wno-reserved-user-defined-literal -Wno-inconsistent-missing-override -fvisibility=hidden -Xclang -load -Xclang /home/zeus/src/chromium/src/third_party/llvm-build/Release+Asserts/lib/libFindBadConstructs.so -Xclang -add-plugin -Xclang find-bad-constructs -Wheader-hygiene -Wstring-conversion -O0 -g2 -gsplit-dwarf -fno-threadsafe-statics -fvisibility-inlines-hidden -Wno-undefined-bool-conversion -Wno-tautological-undefined-compare -std=gnu++11 -fno-rtti -fno-exceptions

CXX := c++
FLAGS := -fno-strict-aliasing -fstack-protector --param=ssp-buffer-size=4 -m64 -march=x86-64 -funwind-tables -fPIC -pipe -pthread -fcolor-diagnostics -Wall -Wendif-labels -Werror -Wno-missing-field-initializers -Wno-unused-parameter -Wno-c++11-narrowing -Wno-char-subscripts -Wno-covered-switch-default -Wno-deprecated-register -Wno-unneeded-internal-declaration -Wno-reserved-user-defined-literal -fvisibility=hidden -Wheader-hygiene -Wstring-conversion -O0 -g2 -gsplit-dwarf -fno-threadsafe-statics -fvisibility-inlines-hidden -Wno-undefined-bool-conversion -Wno-tautological-undefined-compare -fno-rtti -fno-exceptions

CXXFLAGS = -std=gnu++11 $(FLAGS)
CFLAGS = $(FLAGS)
LDFLAGS  :=
INCLUDES := -Ichrome -Ichrome/out/Default/gen -I. -I/home/zeus/src/googletest/include -I/home/zeus/src/googletest

DEFINES := -DUSE_SYMBOLIZE -DUSE_OPENSSL=1 -D_FILE_OFFSET_BITS=64 -D__STDC_CONSTANT_MACROS -D__STDC_FORMAT_MACROS -D_DEBUG -DDYNAMIC_ANNOTATIONS_ENABLED=1 -DWTF_USE_DYNAMIC_ANNOTATIONS=1 -D_GLIBCXX_DEBUG=1 -DGTEST_HAS_POSIX_RE=0 -DGTEST_LANG_CXX11=0 -DGTEST_HAS_RTTI=0 -DUNIT_TEST
LIBS     := -lpthread -levent -licuuc
OBJECTS := \
chrome/base/base64.o \
chrome/base/callback_internal.o \
chrome/base/debug/stack_trace.o \
chrome/base/debug/stack_trace_posix.o \
chrome/base/debug/proc_maps_linux.o \
chrome/base/files/file_util_posix.o \
chrome/base/lazy_instance.o \
chrome/base/logging.o \
chrome/base/memory/ref_counted.o \
chrome/base/memory/weak_ptr.o \
chrome/base/memory/singleton.o \
chrome/base/message_loop/message_pump_libevent.o \
chrome/base/rand_util_posix.o \
chrome/base/strings/string_piece.o \
chrome/base/third_party/symbolize/symbolize.o \
chrome/base/third_party/symbolize/demangle.o \
chrome/base/threading/thread_restrictions.o \
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
crypto/p256_key_exchange_x509.o \
crypto/p256_key_exchange_x509_test.o \
crypto/just_fast_keying.o \
crypto/nonce.o \
crypto/handshake.o \
net/darknet_auth.o \
net/darknet_auth_test.o \
debug/hexdump.o \
/home/zeus/src/googletest/src/gtest-all.o \
/home/zeus/src/googletest/src/gtest_main.o \
/home/zeus/src/boringssl/out/crypto/libcrypto.a chrome/base/debug/alias.o \
chrome/base/debug/debugger_posix.o \
chrome/base/sequence_checker_impl.o \
chrome/base/synchronization/lock_impl_posix.o \
chrome/base/synchronization/lock.o \
chrome/base/threading/platform_thread_posix.o \
chrome/base/threading/sequenced_worker_pool.o \
chrome/base/threading/thread_checker_impl.o \
chrome/base/threading/non_thread_safe_impl.o \
chrome/base/threading/thread_local_posix.o \
chrome/base/strings/string16.o \
chrome/base/files/scoped_file.o \
chrome/base/strings/string_split.o \
chrome/base/strings/string_util.o \
chrome/base/strings/string_util_constants.o \
chrome/base/at_exit.o \
chrome/base/safe_strerror_posix.o \
chrome/base/third_party/dynamic_annotations/dynamic_annotations.o

crypto_test: $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ $(LIBS)

%.o: %.c
	clang $(DEFINES) $(CFLAGS) $(INCLUDES) -c $< -o $@

%.o: %.cc
	$(CXX) $(DEFINES) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f crypto_test *.o /home/zeus/src/googletest/src/gtest-all.o /home/zeus/src/googletest/src/gtest_main.o
	find . -name *.o | xargs rm
