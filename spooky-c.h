/*
// Spooky: a 128-bit noncryptographic hash function
// By Bob Jenkins, public domain
//   Oct 31 2010: alpha, framework + SpookyMix appears right
//   Oct 31 2011: beta, finished all the pieces, passes all the tests
// 
// 4 bytes/cycle for long messages.  Reasonably fast for short messages.
// All 1 or 2 bit deltas achieve avalanche within 1% bias per output bit.
//
// This was developed for and tested on 64-bit x86-compatible processors.
// It assumes the processor is little-endian.  There is a macro
// controlling whether unaligned reads are allowed (by default they are).
*/

#include <stdint.h>

#define SC_NUMVARS 12
#define SC_BLOCKSIZE (SC_NUMVARS * 8)

struct spooky_state {
	uint64_t m_data[SC_NUMVARS];
	uint64_t m_state[SC_NUMVARS];
	size_t m_length;
	unsigned m_remainder;
};

void spooky_init(struct spooky_state *state, uint64_t hash1, uint64_t hash2);
void spooky_update(struct spooky_state *state, const void *msg, size_t len);
void spooky_final(struct spooky_state *state, uint64_t *hash1, uint64_t *hash2);
/* hash1/2 doubles as input parameter for seed1/2 and output for hash1/2 */
void spooky_hash128(const void *message, size_t length, uint64_t *hash1, 
		    uint64_t *hash2);
uint64_t spooky_hash64(const void *message, size_t len, uint64_t seed);
uint32_t spooky_hash32(const void *message, size_t len, uint32_t seed);
void spooky_shorthash(const void *message, size_t length,
		      uint64_t *hash1, uint64_t *hash2);
