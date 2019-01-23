#include <stdlib.h>
#include <string.h>

#include <monocypher.c>
#include <tweetnacl.h>

int main(int argc, char ** argv) 
{
	if (argc < 3)
		abort();

    	u8 n[32], r1[32], r2[32];

    	/* tweetnacl: vulnerable scalar multiplication */
    	crypto_scalarmult_base(r1, n);

	/* monocypher: correct scalar multiplication */
	ge p;
    	ge_scalarmult_base(&p, n);
    	ge_tobytes(r2, &p);

    	/* cmp */
    	if (crypto_verify32(r1, r2) != 0)
		abort();

	return 0;
}
