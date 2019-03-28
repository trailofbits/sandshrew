/* test_monocypher_eddsa.c
 *
 *     Tests:
 *         EdDSA signing fault with all-zero input
 *
 *     Descriptions:
 *     	   Tests sandshrews ability to determine ...
 *
 *     Results:
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "monocypher.c"

int
main(int argc, char *argv[])
{
	uint8_t public_key[32];
	uint8_t zero_key[32] = {0};
		
	crypto_sign_public_key(public_key, (const uint8_t *) argv[1]);
	return 0;
}
