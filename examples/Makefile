######################################################
CC			= gcc

IFLAGS			= -Iinclude

CFLAGS			= -g
LFLAGS 			= -shared -fPIC

OPENSSL_LFLAGS		= -lcrypto -lssl
######################################################

all: test_openssl_md5 test_openssl_bnsqr test_tweetnacl_scalarmult test_monocypher_eddsa	

init:
	mkdir include/

test_openssl_md5: test_openssl_md5.c
	$(CC) $(CFLAGS) -static -o $@ $< $(OPENSSL_LFLAGS)


test_openssl_bnsqr: test_openssl_bnsqr.c
	$(CC) $(CFLAGS) -o $@ $< $(OPENSSL_LFLAGS)


test_tweetnacl_scalarmult: test_tweetnacl_scalarmult.c
	$(CC) $(CFLAGS) -static -o $@ $<


test_monocypher_eddsa: test_monocypher_eddsa.c
	$(CC) $(CFLAGS) -static $(IFLAGS) -o tests/$@ $<

clean:
	rm -rf __pycache__/ mcore_*/
	rm test_openssl_md5 test_openssl_bnsqr test_tweetnacl_scalarmult test_monocypher_eddsa
