//
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
//
// See http://burtleburtle.net/bob/hash/spooky.html for more description.
//

#include <stddef.h>
#include <memory.h>

typedef  unsigned long long uint64;
typedef  unsigned long      uint32;
typedef  unsigned short     uint16;
typedef  unsigned char      uint8;



class Spooky
{
public:
    //
    // Init: initialize the context of a Spooky hash
    //
    void Init(
        uint64 hash1,       // seed1
        uint64 hash2);      // seed2
    
    //
    // Update: add a piece of a message to a Spooky state
    //
    void Update(
        const void *message,  // message fragment
        size_t length);       // length of message fragment in bytes


    //
    // Final: compute the hash for the current Spooky state
    //
    // This does not modify the state; you can keep updating it afterward
    //
    // The result is the same as if SpookyHash() had been called with
    // all the pieces concatenated into one message.
    //
    void Final(
        uint64 *hash1,    // first 64 bits of output hash
        uint64 *hash2);   // second 64 bits of output hash

    //
    // SpookyHash: hash a single message in one call, produce 128-bit output
    //
    static void Hash128(
        const void *message,  // message to hash
        size_t length,        // length of message in bytes
        uint64 *hash1,        // in/out: in seed 1, out hash value 1
        uint64 *hash2);       // in/out: in seed 2, out hash value 2

    //
    // SpookyHash: hash a single message in one call, return 64-bit output
    //
    static uint64 Hash64(
        const void *message,  // message to hash
        size_t length,        // length of message in bytes
        uint64 seed)          // seed
    {
        uint64 hash1 = seed;
        Hash128(message, length, &hash1, &seed);
        return hash1;
    }

    //
    // SpookyHash: hash a single message in one call, produce 32-bit output
    //
    static uint32 Hash32(
        const void *message,  // message to hash
        size_t length,        // length of message in bytes
        uint32 seed)          // seed
    {
        uint64 hash1 = seed, hash2 = seed;
        Hash128(message, length, &hash1, &hash2);
        return (uint32)hash1;
    }

    //
    // This is used if the input is 96 bytes long or longer.
    //
    // The internal state is fully overwritten every 96 bytes.
    // Every input bit appears to cause at least 128 bits of entropy
    // before 96 other bytes are combined, when run forward or backward
    //   For every input bit,
    //   Two inputs differing in just that input bit
    //   Where "differ" means xor or subtraction
    //   And the base value is random
    //   When run forward or backwards one Mix
    //   The internal state will differ by an average of 
    //     72 bits for one pair (vs 64, for 128 bits of entropy)
    //     103 bits for two pairs (vs 96)
    //     125 bits for three pairs (vs 112)
    //     141 bits for four pairs (vs 120)
    //     152 bits for five pairs (vs 124)
    //     160 bits for six pairs (vs 126)
    //
    static inline void Mix(
        const uint64 *data, 
        uint64 &h0,
        uint64 &h1,
        uint64 &h2,
        uint64 &h3,
        uint64 &h4,
        uint64 &h5,
        uint64 &h6,
        uint64 &h7,
        uint64 &h8,
        uint64 &h9,
        uint64 &h10,
        uint64 &h11)
    {
        h0 +=(data)[0];  h11=Rot64(h11,32); h9 ^=h1;  h11+=h10; h1 +=h10;
        h1 +=(data)[1];  h0 =Rot64(h0, 41); h10^=h2;  h0 +=h11; h2 +=h11;
        h2 +=(data)[2];  h1 =Rot64(h1, 12); h11^=h3;  h1 +=h0;  h3 +=h0;
        h3 +=(data)[3];  h2 =Rot64(h2, 24); h0 ^=h4;  h2 +=h1;  h4 +=h1;
        h4 +=(data)[4];  h3 =Rot64(h3, 8);  h1 ^=h5;  h3 +=h2;  h5 +=h2;
        h5 +=(data)[5];  h4 =Rot64(h4, 42); h2 ^=h6;  h4 +=h3;  h6 +=h3;
        h6 +=(data)[6];  h5 =Rot64(h5, 32); h3 ^=h7;  h5 +=h4;  h7 +=h4;
        h7 +=(data)[7];  h6 =Rot64(h6, 13); h4 ^=h8;  h6 +=h5;  h8 +=h5;
        h8 +=(data)[8];  h7 =Rot64(h7, 30); h5 ^=h9;  h7 +=h6;  h9 +=h6;
        h9 +=(data)[9];  h8 =Rot64(h8, 20); h6 ^=h10; h8 +=h7;  h10+=h7;
        h10+=(data)[10]; h9 =Rot64(h9, 47); h7 ^=h11; h9 +=h8;  h11+=h8;
        h11+=(data)[11]; h10=Rot64(h10,16); h8 ^=h0;  h10+=h9;  h0 +=h9;
    }

    //
    // Mix all 12 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3% (it may be better than that)
    // For every pair of input bits,
    // with probability 50 +- 3% (it may be better than that)
    //
    // This does not rely on the last Mix() call having already mixed some.
    // It is likely a faster End() could be found if that fact were used.
    //
    static inline void End(
        uint64 &h0,
        uint64 &h1,
        uint64 &h2,
        uint64 &h3,
        uint64 &h4,
        uint64 &h5,
        uint64 &h6,
        uint64 &h7,
        uint64 &h8,
        uint64 &h9,
        uint64 &h10,
        uint64 &h11)
    {
        // once
      h0 = Rot64(h0,29);    h2 ^= h11;   h0 += h2;
      h1 = Rot64(h1,52);    h3 ^= h0;    h1 += h3;
      h2 = Rot64(h2,31);    h4 ^= h1;    h2 += h4;
      h3 = Rot64(h3,43);    h5 ^= h2;    h3 += h5;
      h4 = Rot64(h4,56);    h6 ^= h3;    h4 += h6;
      h5 = Rot64(h5,34);    h7 ^= h4;    h5 += h7;
      h6 = Rot64(h6,21);    h8 ^= h5;    h6 += h8;
      h7 = Rot64(h7,17);    h9 ^= h6;    h7 += h9;
      h8 = Rot64(h8,44);    h10 ^= h7;   h8 += h10;
      h9 = Rot64(h9,38);    h11 ^= h8;   h9 += h11;
      h10 = Rot64(h10,50);  h0 ^= h9;    h10 += h0;
      h11 = Rot64(h11,50);  h1 ^= h10;   h11 += h1;

        // twice
      h0 = Rot64(h0,29);    h2 ^= h11;   h0 += h2;
      h1 = Rot64(h1,52);    h3 ^= h0;    h1 += h3;
      h2 = Rot64(h2,31);    h4 ^= h1;    h2 += h4;
      h3 = Rot64(h3,43);    h5 ^= h2;    h3 += h5;
      h4 = Rot64(h4,56);    h6 ^= h3;    h4 += h6;
      h5 = Rot64(h5,34);    h7 ^= h4;    h5 += h7;
      h6 = Rot64(h6,21);    h8 ^= h5;    h6 += h8;
      h7 = Rot64(h7,17);    h9 ^= h6;    h7 += h9;
      h8 = Rot64(h8,44);    h10 ^= h7;   h8 += h10;
      h9 = Rot64(h9,38);    h11 ^= h8;   h9 += h11;
      h10 = Rot64(h10,50);  h0 ^= h9;    h10 += h0;
      h11 = Rot64(h11,50);  h1 ^= h10;   h11 += h1;
    }

    //
    // n trials both set and cleared at least m bits of h0 h1 h2 h3
    //   n: 2   m: 29
    //   n: 3   m: 46
    //   n: 4   m: 57
    //   n: 5   m: 107
    //   n: 6   m: 146
    //   n: 7   m: 152
    // when run forwards or backwards
    // for all 1-bit and 2-bit diffs
    // with both xor and subtraction defining diffs
    // with a base of all zeros plus a counter, or plus another bit, or random
    // I added it up; that appears to imply 128 bits of entropy.
    //
    static inline void ShortMix(
        uint64 &h0,
        uint64 &h1,
        uint64 &h2,
        uint64 &h3)
    {
        h2 = Rot64(h2,50);  h2 += h3;  h0 ^= h2;
        h3 = Rot64(h3,52);  h3 += h0;  h1 ^= h3;
        h0 = Rot64(h0,30);  h0 += h1;  h2 ^= h0;
        h1 = Rot64(h1,41);  h1 += h2;  h3 ^= h1;
        h2 = Rot64(h2,54);  h2 += h3;  h0 ^= h2;
        h3 = Rot64(h3,48);  h3 += h0;  h1 ^= h3;
        h0 = Rot64(h0,38);  h0 += h1;  h2 ^= h0;
        h1 = Rot64(h1,37);  h1 += h2;  h3 ^= h1;
        h2 = Rot64(h2,62);  h2 += h3;  h0 ^= h2;
        h3 = Rot64(h3,34);  h3 += h0;  h1 ^= h3;
        h0 = Rot64(h0,5);   h0 += h1;  h2 ^= h0;
        h1 = Rot64(h1,36);  h1 += h2;  h3 ^= h1;
    }

    //
    // Mix all 4 inputs together so that h0, h1 are a hash of them all.
    //
    // For two inputs differing in just the input bits
    // Where "differ" means xor or subtraction
    // And the base value is random, or a counting value starting at that bit
    // The final result will have each bit of h0, h1 flip
    // For every input bit,
    // with probability 50 +- .3% (it is probably better than that)
    // For every pair of input bits,
    // with probability 50 +- .75% (the worst case is approximately that)
    //
    static inline void ShortEnd(
        uint64 &h0,
        uint64 &h1,
        uint64 &h2,
        uint64 &h3)
    {
        h3 ^= h2;  h2 = Rot64(h2,15);  h3 += h2;
        h0 ^= h3;  h3 = Rot64(h3,52);  h0 += h3;
        h1 ^= h0;  h0 = Rot64(h0,26);  h1 += h0;
        h2 ^= h1;  h1 = Rot64(h1,51);  h2 += h1;
        h3 ^= h2;  h2 = Rot64(h2,28);  h3 += h2;
        h0 ^= h3;  h3 = Rot64(h3,9);  h0 += h3;
        h1 ^= h0;  h0 = Rot64(h0,47);   h1 += h0;
        h2 ^= h1;  h1 = Rot64(h1,54);  h2 += h1;
        h3 ^= h2;  h2 = Rot64(h2,32);  h3 += h2;
        h0 ^= h3;  h3 = Rot64(h3,25);  h0 += h3;
        h1 ^= h0;  h0 = Rot64(h0,63);  h1 += h0;
    }
    
    //
    // left rotate a 64-bit value by k bytes
    //
    static inline uint64 Rot64(uint64 x, int k)
    {
        return (x << k) | (x >> (64 - k));
    }

private:

    //
    // ShortHash is used for messages under 96 bytes in length
    // ShortHash has a low startup cost, the normal mode is good for long
    // keys, the cost crossover is at about 96 bytes.  The two modes were
    // held to the same quality bar.
    // 
    static void ShortHash(
        const void *message,
        size_t length,
        uint64 *hash1,
        uint64 *hash2);

    // number of uint64's in internal state
    static const size_t sc_numVars = 12;

    // size of internal state, in bytes
    static const size_t sc_blockSize = sc_numVars*8;

    //
    // sc_const: a constant which:
    //  * is not zero
    //  * is odd
    //  * is a not-very-regular mix of 1's and 0's
    //  * does not need any other special mathematical properties
    //
    static const uint64 sc_const = 0xdeadbeefdeadbeefLL;

    uint64 m_data[sc_numVars];   // unhashed data, for partial messages
    uint64 m_state[sc_numVars];  // internal state of the hash
    size_t m_length;             // total length of the input so far
    uint8  m_remainder;          // length of unhashed data stashed in m_data
};



