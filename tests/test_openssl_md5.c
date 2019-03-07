/* test_openssl_md5.c
 * 
 *	Tests:
 *	    OpenSSL MD5
 *
 *	Description:
 *          This is a test case that utilizes concolic execution 
 *          to determine an input that produces the same hash as a fixed 
 *          concrete input (aka a 'Birthday Attack'), resulting in a hash 
 *          collision.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>


/* create a SANDSHREW_* wrapper over OpenSSL's MD5 for concretization */
unsigned char *
SANDSHREW_MD5(char * input, size_t len, unsigned char * result)
{
	return MD5(input, len, result);
}


int 
main(int argc, char *argv[])
{
	unsigned char * orig_result, * user_result;

	orig_result = SANDSHREW_MD5("s0me_1nput_123", 32, orig_result);
	user_result = SANDSHREW_MD5(argv[1], 32, user_result);

	/* if equal, we generated a hash collision! */ 
	if (__strcmp_ssse3(orig_result, user_result) == 0)
		abort();
	return 0;
}
