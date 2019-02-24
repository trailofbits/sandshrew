/* test_simple.c
 * 
 *      Using concolic execution in order to generate a 
 *      hash collision with MD5.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>

char * benchmark_input = "s0me_1nput_123";

/* for the sake of better parsing, we redefine MD5 */
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md)
{
    MD5_CTX c;
    static unsigned char m[MD5_DIGEST_LENGTH];

    if (md == NULL)
        md = m;
    if (!MD5_Init(&c))
        return NULL;
    
    MD5_Update(&c, d, n);
    MD5_Final(md, &c);
    //OPENSSL_cleanse(&c, sizeof(c)); 
    return md;
}


/*
 * 	In this test case, we create a wrapper over
 * 	OpenSSL's MD5() function. This way, we pass this
 * 	wrapper function to sandshrew, resulting in the
 * 	concretization of MD5().
 */
void md5_wrap(unsigned char * result, char * input, size_t len)
{
	MD5(input, len, result);
}


int main(int argc, char ** argv)
{
	unsigned char orig_result[MD5_DIGEST_LENGTH];
	unsigned char user_result[MD5_DIGEST_LENGTH];

	/* generate MD5 hash from benchmark input */
	md5_wrap(orig_result, benchmark_input, strlen(benchmark_input));

	/* generate MD5 hash from user input */
	md5_wrap(user_result, argv[1], strlen(argv[1]));

	if (strcmp(orig_result, user_result) == 0)
		abort();
	return 0;
}
