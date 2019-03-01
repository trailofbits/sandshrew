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
    return md;
}


/*
 * 	In this test case, we create a wrapper over
 * 	OpenSSL's MD5() function. This way, we pass this
 * 	wrapper function to sandshrew, resulting in the
 * 	concretization of MD5().
 */
unsigned char *md5_wrap(char * input, size_t len, unsigned char * result)
{
	return MD5(input, len, result);
}


int main(int argc, char *argv[])
{
	unsigned char * orig_result;
	unsigned char * user_result;
	char * benchmark_input = "s0me_1nput_123";

	orig_result = md5_wrap(benchmark_input, strlen(benchmark_input), orig_result);
	user_result = md5_wrap(argv[1], 32, user_result);
	
	if (strcmp(orig_result, user_result) == 0)
		abort();
	return 0;
}
