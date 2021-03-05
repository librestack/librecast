#include "test.h"
#include <librecast/crypto.h>

int main()
{
	char in1[] = "hash this";
	char in2[] = "hash that";
	unsigned char hash1[HASHSIZE];
	unsigned char hash2[HASHSIZE];
	hash_state state;

	test_name("hash_init() / hash_update() / hash_final()");

	hash_generic(hash1, HASHSIZE, (unsigned char *)in1, strlen(in1));
	hash_generic(hash2, HASHSIZE, (unsigned char *)in2, strlen(in2));

	test_assert(memcmp(hash1, hash2, HASHSIZE), "hashes must differ");

	hash_init(&state, NULL, 0, HASHSIZE);
	hash_update(&state, (unsigned char *)in1, HASHSIZE);
	hash_final(&state, hash2, HASHSIZE);

	/* TODO: tests with keys etc. */

	return fails;
}
