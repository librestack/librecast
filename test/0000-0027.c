#include "test.h"
#include "../src/hash.h"

int main()
{
	char in1[] = "hash this";
	char in2[] = "hash that";
	unsigned char hash1[HASHSIZE];
	unsigned char hash2[HASHSIZE];
	hash_state state;

	test_name("hash.h");

	hash_generic(hash1, HASHSIZE, (unsigned char *)in1, strlen(in1));
	hash_generic(hash2, HASHSIZE, (unsigned char *)in2, strlen(in2));

	test_assert(memcmp(hash1, hash2, HASHSIZE), "hashes must differ");

	test_assert(hash_init(&state, NULL, 0, HASHSIZE) == 0,
			"hash_init success");
	test_assert(hash_update(&state, (unsigned char *)in1, HASHSIZE) == 0,
			"hash_init success");
	test_assert(hash_final(&state, hash2, HASHSIZE) == 0,
			"hash_final success");

	/* TODO: tests with keys etc. */

	return fails;
}
