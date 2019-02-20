/*
 * test_pack25519.c
 *
 * 	Equivalence test for correctness between
 * 	ECDLP implementations in 'tiny crypto', including
 * 	TweeNaCL and Monocypher
 */

#include <monocypher.c>
#include <tweetnacl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char ** argv)
{
	/* instantiate buffers for storing results */
	uint8_t r1[32], r2[32];

    /* tweetnacl: vulnerable scalar multiplication */
	crypto_scalarmult_curve25519_tweet_base(r1, (const uint8_t *) argv[1]);

	/* monocypher */
	ge A;
	ge_scalarmult_base(&A, (uint8_t *) argv[1]);
	ge_tobytes(r2, &A);

	/*
	printf("tweetnacl: ");
	for (int i = 0; i < strlen(r1); i++)
		printf("%02X", r1[i]);
	printf("\n\n");

	printf("monocypher: ");
	for (int i = 0; i < strlen(r2); i++)
	    printf("%02X", r2[i]);
	printf("\n");
	*/

	/* compare implementations - use function models to aid */
	if (memcmp(r1, r2, 32) != 0)
		abort();

	return 0;
}
