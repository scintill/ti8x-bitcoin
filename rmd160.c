/* LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

/* Implementation of LTC_RIPEMD-160 based on the source by Antoon Bosselaers, ESAT-COSIC
 *
 * This source has been radically overhauled to be portable and work within
 * the LibTomCrypt API by Tom St Denis
 */
#include "rmd160.h"

/* helper definitions */

/* ROLc(x, n) cyclically rotates x over n bits to the left */
/* x must be of an unsigned 32 bits type and 0 <= n < 32. */
#ifndef TI8X
inline
#endif
static mr_unsign32 ROLc(mr_unsign32 x, unsigned char n) {
	return (((x) << (n)) | ((x) >> (32-(n))));
}

/* the five basic functions F(), G() and H() */
// SDCC seems to compile smaller with these left as macros
#define F(x, y, z)        ((x) ^ (y) ^ (z))
#define G(x, y, z)        (((x) & (y)) | (~(x) & (z)))
#define H(x, y, z)        (((x) | ~(y)) ^ (z))
#define I(x, y, z)        (((x) & (z)) | ((y) & ~(z)))
#define J(x, y, z)        ((x) ^ ((y) | ~(z)))

/* the ten basic operations FF() through III() */
#ifndef TI8X
inline
#endif
static void FF(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
  *pa += F(b, *pc, d) + x;
  *pa = ROLc(*pa, s) + e;
  *pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void GG(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += G(b, *pc, d) + x + 0x5a827999UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void HH(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += H(b, *pc, d) + x + 0x6ed9eba1UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void II(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += I(b, *pc, d) + x + 0x8f1bbcdcUL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void JJ(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += J(b, *pc, d) + x + 0xa953fd4eUL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void FFF(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += F(b, *pc, d) + x;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void GGG(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += G(b, *pc, d) + x + 0x7a6d76e9UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void HHH(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += H(b, *pc, d) + x + 0x6d703ef3UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void III(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += I(b, *pc, d) + x + 0x5c4dd124UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}

#ifndef TI8X
inline
#endif
static void JJJ(mr_unsign32 *pa, mr_unsign32 b, mr_unsign32 *pc, mr_unsign32 d, mr_unsign32 e, mr_unsign32 x, unsigned char s) {
	*pa += J(b, *pc, d) + x + 0x50a28be6UL;
	*pa = ROLc(*pa, s) + e;
	*pc = ROLc(*pc, 10);
}


void rmd160_compress(hash_state *md, unsigned char *buf) {
   mr_unsign32 aa,bb,cc,dd,ee,aaa,bbb,ccc,ddd,eee,X[16];
   int i;

   /* load words X */
   for (i = 0; i < 16; i++) {
      X[i] = ((mr_unsign32*)buf)[i];
   }

   /* load state */
   aa = aaa = md->rmd160.out[0];
   bb = bbb = md->rmd160.out[1];
   cc = ccc = md->rmd160.out[2];
   dd = ddd = md->rmd160.out[3];
   ee = eee = md->rmd160.out[4];

   /* round 1 */
   FF(&aa, bb, &cc, dd, ee, X[ 0], 11);
   FF(&ee, aa, &bb, cc, dd, X[ 1], 14);
   FF(&dd, ee, &aa, bb, cc, X[ 2], 15);
   FF(&cc, dd, &ee, aa, bb, X[ 3], 12);
   FF(&bb, cc, &dd, ee, aa, X[ 4],  5);
   FF(&aa, bb, &cc, dd, ee, X[ 5],  8);
   FF(&ee, aa, &bb, cc, dd, X[ 6],  7);
   FF(&dd, ee, &aa, bb, cc, X[ 7],  9);
   FF(&cc, dd, &ee, aa, bb, X[ 8], 11);
   FF(&bb, cc, &dd, ee, aa, X[ 9], 13);
   FF(&aa, bb, &cc, dd, ee, X[10], 14);
   FF(&ee, aa, &bb, cc, dd, X[11], 15);
   FF(&dd, ee, &aa, bb, cc, X[12],  6);
   FF(&cc, dd, &ee, aa, bb, X[13],  7);
   FF(&bb, cc, &dd, ee, aa, X[14],  9);
   FF(&aa, bb, &cc, dd, ee, X[15],  8);

   /* round 2 */
   GG(&ee, aa, &bb, cc, dd, X[ 7],  7);
   GG(&dd, ee, &aa, bb, cc, X[ 4],  6);
   GG(&cc, dd, &ee, aa, bb, X[13],  8);
   GG(&bb, cc, &dd, ee, aa, X[ 1], 13);
   GG(&aa, bb, &cc, dd, ee, X[10], 11);
   GG(&ee, aa, &bb, cc, dd, X[ 6],  9);
   GG(&dd, ee, &aa, bb, cc, X[15],  7);
   GG(&cc, dd, &ee, aa, bb, X[ 3], 15);
   GG(&bb, cc, &dd, ee, aa, X[12],  7);
   GG(&aa, bb, &cc, dd, ee, X[ 0], 12);
   GG(&ee, aa, &bb, cc, dd, X[ 9], 15);
   GG(&dd, ee, &aa, bb, cc, X[ 5],  9);
   GG(&cc, dd, &ee, aa, bb, X[ 2], 11);
   GG(&bb, cc, &dd, ee, aa, X[14],  7);
   GG(&aa, bb, &cc, dd, ee, X[11], 13);
   GG(&ee, aa, &bb, cc, dd, X[ 8], 12);

   /* round 3 */
   HH(&dd, ee, &aa, bb, cc, X[ 3], 11);
   HH(&cc, dd, &ee, aa, bb, X[10], 13);
   HH(&bb, cc, &dd, ee, aa, X[14],  6);
   HH(&aa, bb, &cc, dd, ee, X[ 4],  7);
   HH(&ee, aa, &bb, cc, dd, X[ 9], 14);
   HH(&dd, ee, &aa, bb, cc, X[15],  9);
   HH(&cc, dd, &ee, aa, bb, X[ 8], 13);
   HH(&bb, cc, &dd, ee, aa, X[ 1], 15);
   HH(&aa, bb, &cc, dd, ee, X[ 2], 14);
   HH(&ee, aa, &bb, cc, dd, X[ 7],  8);
   HH(&dd, ee, &aa, bb, cc, X[ 0], 13);
   HH(&cc, dd, &ee, aa, bb, X[ 6],  6);
   HH(&bb, cc, &dd, ee, aa, X[13],  5);
   HH(&aa, bb, &cc, dd, ee, X[11], 12);
   HH(&ee, aa, &bb, cc, dd, X[ 5],  7);
   HH(&dd, ee, &aa, bb, cc, X[12],  5);

   /* round 4 */
   II(&cc, dd, &ee, aa, bb, X[ 1], 11);
   II(&bb, cc, &dd, ee, aa, X[ 9], 12);
   II(&aa, bb, &cc, dd, ee, X[11], 14);
   II(&ee, aa, &bb, cc, dd, X[10], 15);
   II(&dd, ee, &aa, bb, cc, X[ 0], 14);
   II(&cc, dd, &ee, aa, bb, X[ 8], 15);
   II(&bb, cc, &dd, ee, aa, X[12],  9);
   II(&aa, bb, &cc, dd, ee, X[ 4],  8);
   II(&ee, aa, &bb, cc, dd, X[13],  9);
   II(&dd, ee, &aa, bb, cc, X[ 3], 14);
   II(&cc, dd, &ee, aa, bb, X[ 7],  5);
   II(&bb, cc, &dd, ee, aa, X[15],  6);
   II(&aa, bb, &cc, dd, ee, X[14],  8);
   II(&ee, aa, &bb, cc, dd, X[ 5],  6);
   II(&dd, ee, &aa, bb, cc, X[ 6],  5);
   II(&cc, dd, &ee, aa, bb, X[ 2], 12);

   /* round 5 */
   JJ(&bb, cc, &dd, ee, aa, X[ 4],  9);
   JJ(&aa, bb, &cc, dd, ee, X[ 0], 15);
   JJ(&ee, aa, &bb, cc, dd, X[ 5],  5);
   JJ(&dd, ee, &aa, bb, cc, X[ 9], 11);
   JJ(&cc, dd, &ee, aa, bb, X[ 7],  6);
   JJ(&bb, cc, &dd, ee, aa, X[12],  8);
   JJ(&aa, bb, &cc, dd, ee, X[ 2], 13);
   JJ(&ee, aa, &bb, cc, dd, X[10], 12);
   JJ(&dd, ee, &aa, bb, cc, X[14],  5);
   JJ(&cc, dd, &ee, aa, bb, X[ 1], 12);
   JJ(&bb, cc, &dd, ee, aa, X[ 3], 13);
   JJ(&aa, bb, &cc, dd, ee, X[ 8], 14);
   JJ(&ee, aa, &bb, cc, dd, X[11], 11);
   JJ(&dd, ee, &aa, bb, cc, X[ 6],  8);
   JJ(&cc, dd, &ee, aa, bb, X[15],  5);
   JJ(&bb, cc, &dd, ee, aa, X[13],  6);

   /* parallel round 1 */
   JJJ(&aaa, bbb, &ccc, ddd, eee, X[ 5],  8);
   JJJ(&eee, aaa, &bbb, ccc, ddd, X[14],  9);
   JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 7],  9);
   JJJ(&ccc, ddd, &eee, aaa, bbb, X[ 0], 11);
   JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 9], 13);
   JJJ(&aaa, bbb, &ccc, ddd, eee, X[ 2], 15);
   JJJ(&eee, aaa, &bbb, ccc, ddd, X[11], 15);
   JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 4],  5);
   JJJ(&ccc, ddd, &eee, aaa, bbb, X[13],  7);
   JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 6],  7);
   JJJ(&aaa, bbb, &ccc, ddd, eee, X[15],  8);
   JJJ(&eee, aaa, &bbb, ccc, ddd, X[ 8], 11);
   JJJ(&ddd, eee, &aaa, bbb, ccc, X[ 1], 14);
   JJJ(&ccc, ddd, &eee, aaa, bbb, X[10], 14);
   JJJ(&bbb, ccc, &ddd, eee, aaa, X[ 3], 12);
   JJJ(&aaa, bbb, &ccc, ddd, eee, X[12],  6);

   /* parallel round 2 */
   III(&eee, aaa, &bbb, ccc, ddd, X[ 6],  9);
   III(&ddd, eee, &aaa, bbb, ccc, X[11], 13);
   III(&ccc, ddd, &eee, aaa, bbb, X[ 3], 15);
   III(&bbb, ccc, &ddd, eee, aaa, X[ 7],  7);
   III(&aaa, bbb, &ccc, ddd, eee, X[ 0], 12);
   III(&eee, aaa, &bbb, ccc, ddd, X[13],  8);
   III(&ddd, eee, &aaa, bbb, ccc, X[ 5],  9);
   III(&ccc, ddd, &eee, aaa, bbb, X[10], 11);
   III(&bbb, ccc, &ddd, eee, aaa, X[14],  7);
   III(&aaa, bbb, &ccc, ddd, eee, X[15],  7);
   III(&eee, aaa, &bbb, ccc, ddd, X[ 8], 12);
   III(&ddd, eee, &aaa, bbb, ccc, X[12],  7);
   III(&ccc, ddd, &eee, aaa, bbb, X[ 4],  6);
   III(&bbb, ccc, &ddd, eee, aaa, X[ 9], 15);
   III(&aaa, bbb, &ccc, ddd, eee, X[ 1], 13);
   III(&eee, aaa, &bbb, ccc, ddd, X[ 2], 11);

   /* parallel round 3 */
   HHH(&ddd, eee, &aaa, bbb, ccc, X[15],  9);
   HHH(&ccc, ddd, &eee, aaa, bbb, X[ 5],  7);
   HHH(&bbb, ccc, &ddd, eee, aaa, X[ 1], 15);
   HHH(&aaa, bbb, &ccc, ddd, eee, X[ 3], 11);
   HHH(&eee, aaa, &bbb, ccc, ddd, X[ 7],  8);
   HHH(&ddd, eee, &aaa, bbb, ccc, X[14],  6);
   HHH(&ccc, ddd, &eee, aaa, bbb, X[ 6],  6);
   HHH(&bbb, ccc, &ddd, eee, aaa, X[ 9], 14);
   HHH(&aaa, bbb, &ccc, ddd, eee, X[11], 12);
   HHH(&eee, aaa, &bbb, ccc, ddd, X[ 8], 13);
   HHH(&ddd, eee, &aaa, bbb, ccc, X[12],  5);
   HHH(&ccc, ddd, &eee, aaa, bbb, X[ 2], 14);
   HHH(&bbb, ccc, &ddd, eee, aaa, X[10], 13);
   HHH(&aaa, bbb, &ccc, ddd, eee, X[ 0], 13);
   HHH(&eee, aaa, &bbb, ccc, ddd, X[ 4],  7);
   HHH(&ddd, eee, &aaa, bbb, ccc, X[13],  5);

   /* parallel round 4 */
   GGG(&ccc, ddd, &eee, aaa, bbb, X[ 8], 15);
   GGG(&bbb, ccc, &ddd, eee, aaa, X[ 6],  5);
   GGG(&aaa, bbb, &ccc, ddd, eee, X[ 4],  8);
   GGG(&eee, aaa, &bbb, ccc, ddd, X[ 1], 11);
   GGG(&ddd, eee, &aaa, bbb, ccc, X[ 3], 14);
   GGG(&ccc, ddd, &eee, aaa, bbb, X[11], 14);
   GGG(&bbb, ccc, &ddd, eee, aaa, X[15],  6);
   GGG(&aaa, bbb, &ccc, ddd, eee, X[ 0], 14);
   GGG(&eee, aaa, &bbb, ccc, ddd, X[ 5],  6);
   GGG(&ddd, eee, &aaa, bbb, ccc, X[12],  9);
   GGG(&ccc, ddd, &eee, aaa, bbb, X[ 2], 12);
   GGG(&bbb, ccc, &ddd, eee, aaa, X[13],  9);
   GGG(&aaa, bbb, &ccc, ddd, eee, X[ 9], 12);
   GGG(&eee, aaa, &bbb, ccc, ddd, X[ 7],  5);
   GGG(&ddd, eee, &aaa, bbb, ccc, X[10], 15);
   GGG(&ccc, ddd, &eee, aaa, bbb, X[14],  8);

   /* parallel round 5 */
   FFF(&bbb, ccc, &ddd, eee, aaa, X[12] ,  8);
   FFF(&aaa, bbb, &ccc, ddd, eee, X[15] ,  5);
   FFF(&eee, aaa, &bbb, ccc, ddd, X[10] , 12);
   FFF(&ddd, eee, &aaa, bbb, ccc, X[ 4] ,  9);
   FFF(&ccc, ddd, &eee, aaa, bbb, X[ 1] , 12);
   FFF(&bbb, ccc, &ddd, eee, aaa, X[ 5] ,  5);
   FFF(&aaa, bbb, &ccc, ddd, eee, X[ 8] , 14);
   FFF(&eee, aaa, &bbb, ccc, ddd, X[ 7] ,  6);
   FFF(&ddd, eee, &aaa, bbb, ccc, X[ 6] ,  8);
   FFF(&ccc, ddd, &eee, aaa, bbb, X[ 2] , 13);
   FFF(&bbb, ccc, &ddd, eee, aaa, X[13] ,  6);
   FFF(&aaa, bbb, &ccc, ddd, eee, X[14] ,  5);
   FFF(&eee, aaa, &bbb, ccc, ddd, X[ 0] , 15);
   FFF(&ddd, eee, &aaa, bbb, ccc, X[ 3] , 13);
   FFF(&ccc, ddd, &eee, aaa, bbb, X[ 9] , 11);
   FFF(&bbb, ccc, &ddd, eee, aaa, X[11] , 11);

   /* combine results */
   ddd += cc + md->rmd160.out[1];               /* final result for md->rmd160.out[0] */
   md->rmd160.out[1] = md->rmd160.out[2] + dd + eee;
   md->rmd160.out[2] = md->rmd160.out[3] + ee + aaa;
   md->rmd160.out[3] = md->rmd160.out[4] + aa + bbb;
   md->rmd160.out[4] = md->rmd160.out[0] + bb + ccc;
   md->rmd160.out[0] = ddd;
}

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
*/
void rmd160_init(hash_state * md) {
   md->rmd160.out[0] = 0x67452301UL;
   md->rmd160.out[1] = 0xefcdab89UL;
   md->rmd160.out[2] = 0x98badcfeUL;
   md->rmd160.out[3] = 0x10325476UL;
   md->rmd160.out[4] = 0xc3d2e1f0UL;
   md->rmd160.curlen   = 0;
   md->rmd160.length   = 0;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
*/
void rmd160_done(hash_state * md) {
    /* increase the length of the message */
    md->rmd160.length += md->rmd160.curlen;

    /* append the '1' bit */
    md->rmd160.buf.buf8[md->rmd160.curlen++] = (unsigned char)0x80;

	// XXX removing for our simplified purposes
#if 0
    /* if the length is currently above 56 bytes we append zeros
     * then compress.  Then we can fall back to padding zeros and length
     * encoding like normal.
     */
    if (md->rmd160.curlen > 56) {
        while (md->rmd160.curlen < 64) {
            md->rmd160.buf.buf8[md->rmd160.curlen++] = (unsigned char)0;
        }
        rmd160_compress(md, md->rmd160.buf.buf8);
        md->rmd160.curlen = 0;
    }
#endif

    /* pad upto 56 bytes of zeroes */
    while (md->rmd160.curlen < 56) {
        md->rmd160.buf.buf8[md->rmd160.curlen++] = (unsigned char)0;
    }

    /* store length */
	md->rmd160.buf.buf32[14] = md->rmd160.length * 8;
	md->rmd160.buf.buf32[15] = 0;
    rmd160_compress(md, md->rmd160.buf.buf8);
}
