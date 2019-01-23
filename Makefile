CC		= gcc
IFLAGS		= -Iinclude
CFLAGS		= -g -static -Wall
LFLAGS 		= -g -shared -fPIC
SRCS		= include/rng.c include/tweetnacl.c

%: tests/%.c
	$(CC) $(CFLAGS) $(IFLAGS) $(COMPILE) -o tests/$@ $< $(SRCS)
	$(CC) $(LFLAGS) $(IFLAGS) $(COMPILE) -o tests/$@.so $< $(SRCS)

prepare:
	mkdir include
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.c -O include/monocypher.c
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.h -O include/monocypher.h
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.c -O include/tweetnacl.c
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.h -O include/tweetnacl.h
	wget https://raw.githubusercontent.com/ultramancool/tweetnacl-usable/master/randombytes.c -O include/rng.c

clean:
	rm -rf include/ __pycache__/ mcore_*/
	rm tests/*.so tests/test_pack25519
	rm a.out