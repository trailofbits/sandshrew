/* test_openssl_bnsqr.c
 *
 *	Tests:
 *		OpenSSL Bignum Squaring
 *
 *	Description:
 *		Tests invariance between sqr and self-multiplication
 *		in OpenSSL BN_sqr() implementation
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>


int
main(int argc, char *argv[])
{
	BN_CTX *ctx = BN_CTX_new();
	BIGNUM *x = BN_new();
	BIGNUM *r1 = BN_new();
	BIGNUM *r2 = BN_new();

	BN_bin2bn(argv[1], 32, x);

	/* TODO: write wrappers */
	BN_sqr(r1, x, ctx);
	BN_mul(r2, x, x, ctx);

	if (BN_cmp(r1, r2) != 0)
		abort();
	
	/* unsafe: no frees */
	return 0;
}
