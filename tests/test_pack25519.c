#include <string.h>
#include <stdlib.h>

#include <monocypher.c>
#include <tweetnacl.h>

int main(int argc, char ** argv) 
{
    	u8 r1[32], r2[32];

    	/* tweetnacl: vulnerable scalar multiplication */
    	crypto_scalarmult_base(r1, (const u8 *) argv[1]);

	/* monocypher: correct scalar multiplication */
	ge p;
    	ge_scalarmult_base(&p, (const u8 *) argv[1]);
    	ge_tobytes(r2, &p);

	/* compare implementations - use function models to aid */
	if (crypto_verify_32(r1, r2) != 0)
		abort();
	
	return 0;
}
