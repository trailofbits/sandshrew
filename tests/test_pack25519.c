/*
 * test_pack25519.c
 *
 * 	Equivalence test for correctness between
 * 	ECDLP implementations in 'tiny crypto', including
 * 	TweeNaCL and Monocypher
 */

#include <monocypher.h>
#include <tweetnacl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


uint8_t * SANDSHREW_crypto_sign_public_key(const uint8_t sk[32])
{
    uint8_t pk[32];
    crypto_sign_public_key(pk, sk);
    return pk;
}


uint8_t * SANDSHREW_crypto_scalarmult_curve25519_tweet_base(const uint8_t in[32])
{
    uint8_t res[32];
    crypto_scalarmult_curve25519_tweet_base(res, in);
    return res;
}


int main(int argc, char ** argv)
{
	/* instantiate buffers for storing results */
	uint8_t * r1, * r2;

    	r1 = SANDSHREW_crypto_scalarmult_curve25519_tweet_base((const uint8_t *) argv[1]);
    	r2 = SANDSHREW_crypto_sign_public_key((const uint8_t *) argv[1]);

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
	if (strcmp(r1, r2) != 0)
		abort();

	return 0;
}
