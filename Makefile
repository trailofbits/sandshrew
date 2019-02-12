CC		= gcc
IFLAGS		= -L/usr/local/lib -Iinclude
CFLAGS		= -z muldefs
LFLAGS 		= -shared -fPIC
SRCS		= include/rng.c include/tweetnacl.c
LDFLAGS		= -lsodium

%: tests/%.c
	$(CC) -g $(CFLAGS) $(IFLAGS) -o tests/$@ $< $(SRCS) $(LDFLAGS)
	$(CC) -g $(CFLAGS) $(LFLAGS) $(IFLAGS) -o tests/$@.so $< $(SRCS) $(LDFLAGS)

prepare:
	mkdir include/ utils/
	git clone https://github.com/eliben/pycparser.git
	mv pycparser/utils/fake_libc_include utils/fake_libc_include
	rm -rf pycparser
.PHONY: prepare

crypto:
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.c -O include/monocypher.c
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.h -O include/monocypher.h
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.c -O include/tweetnacl.c
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.h -O include/tweetnacl.h
	wget https://raw.githubusercontent.com/ultramancool/tweetnacl-usable/master/randombytes.c -O include/rng.c

clean:
	rm -rf include/ __pycache__/ mcore_*/
	rm tests/*.so tests/test_pack25519
	rm a.out
