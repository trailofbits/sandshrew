/*
 * test_pack25519.c
 *
 * 	Equivalence test for correctness between
 * 	ECDLP implementations in 'tiny crypto', including
 * 	TweeNaCL and Monocypher
 */
#include <monocypher.c>
#include <tweetnacl.h>

int main(int argc, char ** argv) 
{
	/* instantiate buffers for storing results */
	u8 r1[32], r2[32] = { 0 };

    	/* tweetnacl: vulnerable scalar multiplication */
	crypto_scalarmult_base(r1, (const u8 *) argv[1]);
	trim_scalar(r1);

	/* monocypher: correct scalar multiplication */
	ge p;
    	ge_scalarmult_base(&p, (const u8 *) argv[1]); 
    	ge_tobytes(r2, &p);
	WIPE_CTX(&p);

	/* compare implementations - use function models to aid */
	if (crypto_verify_32(r1, r2) != 0)
		return -1;

	return 0;
}
