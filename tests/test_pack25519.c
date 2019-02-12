/*
 * test_pack25519.c
 *
 * 	Equivalence test for correctness between
 * 	ECDLP implementations in 'tiny crypto', including
 * 	TweeNaCL and Monocypher
 */

#include <tweetnacl.c>
#include <sodium.h>

#include <stdlib.h>
#include <string.h>


int main(int argc, char ** argv)
{
	if (sodium_init() < 0)
		return -1;
	
	/* instantiate buffers for storing results */
	uint8_t r1[32], r2[32];

    	/* tweetnacl: vulnerable scalar multiplication */
	crypto_scalarmult_curve25519_tweet_base(r1, (const uint8_t *) argv[1]);

	/* libsodium: correct scalar multiplication */
	crypto_scalarmult_curve25519_base(r2, (const uint8_t *) argv[1]);

	/* compare implementations - use function models to aid */
	if (memcmp(r1, r2, 32) != 0)
		abort();

	return 0;
}
