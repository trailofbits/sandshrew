######################################################
CC			= gcc

IFLAGS			= -Iinclude

CFLAGS			= -g
LFLAGS 			= -shared -fPIC

TWEETNACL_SRCS		= include/rng.c include/tweetnacl.c
OPENSSL_LFLAGS		= -lcrypto -lssl
######################################################

all: test_openssl_md5 test_pack25519


test_openssl_md5: tests/test_openssl_md5.c
	$(CC) $(CFLAGS) -static -o tests/$@ $< $(OPENSSL_LFLAGS)


test_openssl_bnsqr: tests/test_openssl_bnsqr.c
	$(CC) $(CFLAGS) $(IFLAGS) -o tests/$@ $< $(OPENSSL_LFLAGS)


test_tweetnacl_scalarmult: tests/test_tweetnacl_scalarmult.c
	$(CC) $(CFLAGS) -static $(IFLAGS) -o tests/$@ $< $(TWEETNACL_SRCS)


clean:
	rm -rf __pycache__/ mcore_*/
	rm tests/test_openssl_md5 tests/test_openssl_bnsqr tests/test_tweetnacl_scalarmult
