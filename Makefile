CC		= gcc
IFLAGS		= -Iinclude/monocypher -Iinclude/tweetnacl
CFLAGS		= -g -static -Wall
LFLAGS 		= -shared -fPIC
SRCS		= include/tweetnacl/rng.c include/tweetnacl/tweetnacl.c

%: tests/%.c
	$(CC) $(CFLAGS) $(IFLAGS) $(COMPILE) -o tests/$@ $< $(SRCS)
	$(CC) $(LFLAGS) $(IFLAGS) $(COMPILE) -o tests/$@.so $< $(SRCS)

prepare:
	mkdir include include/tweetnacl include/monocypher 
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.c -O include/tweetnacl/tweetnacl.c
	wget https://tweetnacl.cr.yp.to/20131229/tweetnacl.h -O include/tweetnacl/tweetnacl.h
	wget https://raw.githubusercontent.com/ultramancool/tweetnacl-usable/master/randombytes.c -O include/tweetnacl/rng.c
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.c -O include/monocypher/monocypher.c
	wget https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src/monocypher.h -O include/monocypher/monocypher.h

clean:
	rm -rf include/ __pycache__/ mcore_*/
	rm tests/*.so tests/test_pack25519
	rm a.out
