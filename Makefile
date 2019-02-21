######################################################
CC			= gcc

IFLAGS			= -Iinclude

CFLAGS			= -g
LFLAGS 			= -shared -fPIC

TWEETNACL_SRCS		= include/rng.c include/tweetnacl.c
######################################################

all: prepare test_simple test_pack25519


test_simple: tests/test_simple.c
	$(CC) $(CFLAGS) -static -o tests/$@ $< -lcrypto -lssl
	$(CC) $(CFLAGS) $(LFLAGS) -o tests/$@.so $< -lcrypto -lssl


test_pack25519: tests/test_pack25519.c
	$(CC) $(CFLAGS) -static $(IFLAGS) -o tests/$@ $< $(TWEETNACL_SRCS)
	$(CC) $(CFLAGS) $(LFLAGS) $(IFLAGS) -o tests/$@.so $< $(TWEETNACL_SRCS)


prepare:
	mkdir include/ utils/
	git clone https://github.com/eliben/pycparser.git
	mv pycparser/utils/fake_libc_include utils/fake_libc_include
	rm -rf pycparser


clean:
	rm -rf include/ __pycache__/ mcore_*/
	rm tests/*.so tests/test_pack25519
	rm a.out
