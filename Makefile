######################################################
CC			= gcc

IFLAGS			= -Iinclude

CFLAGS			= -g
LFLAGS 			= -shared -fPIC

TWEETNACL_SRCS		= include/rng.c include/tweetnacl.c
######################################################

all: test_openssl_md5 test_pack25519


test_openssl_md5: tests/test_openssl_md5.c
	$(CC) $(CFLAGS) -static -o tests/$@ $< -lcrypto -lssl


test_pack25519: tests/test_pack25519.c
	$(CC) $(CFLAGS) -static $(IFLAGS) -o tests/$@ $< $(TWEETNACL_SRCS)


clean:
	rm -rf __pycache__/ mcore_*/
	rm tests/test_openssl_md5 tests/test_pack25519
