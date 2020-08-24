#ifndef _JHASH_KERNEL_
#define _JHASH_KERNEL_
/* copy paste of jhash from kernel sources to make sure llvm
 * can compile it into valid sequence of bpf instructions
 */

static inline unsigned rol32(unsigned word, unsigned int shift)
{
  return (word << shift) | (word >> ((-shift) & 31));
}

#define __jhash_mix(a, b, c)      \
{           \
  a -= c;  a ^= rol32(c, 4);  c += b; \
  b -= a;  b ^= rol32(a, 6);  a += c; \
  c -= b;  c ^= rol32(b, 8);  b += a; \
  a -= c;  a ^= rol32(c, 16); c += b; \
  b -= a;  b ^= rol32(a, 19); a += c; \
  c -= b;  c ^= rol32(b, 4);  b += a; \
}

#define __jhash_final(a, b, c)      \
{           \
  c ^= b; c -= rol32(b, 14);    \
  a ^= c; a -= rol32(c, 11);    \
  b ^= a; b -= rol32(a, 25);    \
  c ^= b; c -= rol32(b, 16);    \
  a ^= c; a -= rol32(c, 4);   \
  b ^= a; b -= rol32(a, 14);    \
  c ^= b; c -= rol32(b, 24);    \
}

#define JHASH_INITVAL   0xdeadbeef

static inline unsigned jhash(const void *key, unsigned length, unsigned initval)
{
  unsigned a, b, c;
  const unsigned char *k = (const unsigned char*)key;

  a = b = c = JHASH_INITVAL + length + initval;

  while (length > 12) {
    a += *(unsigned *)(k);
    b += *(unsigned *)(k + 4);
    c += *(unsigned *)(k + 8);
    __jhash_mix(a, b, c);
    length -= 12;
    k += 12;
  }
  switch (length) {
  case 12: c += (unsigned)k[11]<<24;
  case 11: c += (unsigned)k[10]<<16;
  case 10: c += (unsigned)k[9]<<8;
  case 9:  c += k[8];
  case 8:  b += (unsigned)k[7]<<24;
  case 7:  b += (unsigned)k[6]<<16;
  case 6:  b += (unsigned)k[5]<<8;
  case 5:  b += k[4];
  case 4:  a += (unsigned)k[3]<<24;
  case 3:  a += (unsigned)k[2]<<16;
  case 2:  a += (unsigned)k[1]<<8;
  case 1:  a += k[0];
     __jhash_final(a, b, c);
  case 0: /* Nothing left to add */
    break;
  }

  return c;
}

static inline unsigned __jhash_nwords(unsigned a, unsigned b, unsigned c, unsigned initval)
{
  a += initval;
  b += initval;
  c += initval;
  __jhash_final(a, b, c);
  return c;
}

//static inline unsigned jhash_2words_cheetah(int a, int b, int initval)
//{
//    return jhash_2words(a, b, initval);
//}

static inline unsigned jhash_2words(unsigned a, unsigned b, unsigned initval)
{
  return __jhash_nwords(a, b, 0, initval + JHASH_INITVAL + (2 << 2));
}

static inline unsigned jhash_1word(unsigned a, unsigned initval)
{
  return __jhash_nwords(a, 0, 0, initval + JHASH_INITVAL + (1 << 2));
}

#endif

