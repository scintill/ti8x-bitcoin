#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "miracl.h"

#define CURVE_BITS 256
#define WORDS 4

static const mr_small rom[]={
0xfffffffefffffc2f,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,
0xbfd25e8cd0364141,0xbaaedce6af48a03b,0xfffffffffffffffe,0xffffffffffffffff,
0x59f2815b16f81798,0x29bfcdb2dce28d9,0x55a06295ce870b07,0x79be667ef9dcbbac,
0x9c47d08ffb10d4b8,0xfd17b448a6855419,0x5da4fbfc0e1108a8,0x483ada7726a3c465};

void otbase58num(miracl *mip, flash num, FILE *fp);

int main()
{
    int ep;
    epoint *g,*w;
    big a,b,p,q,x,y,d;
    long seed;
	int promptr;
	miracl *mip;

    mip = mirsys(CURVE_BITS/4,16);  /* Use Hex internally */
    p=mirvar(0);
    a=mirvar(0);
    b=mirvar(7);
    q=mirvar(0);
    x=mirvar(0);
    y=mirvar(0);
    d=mirvar(0);

	promptr = 0;
	init_big_from_rom(p,WORDS,rom,WORDS*4,&promptr);
	init_big_from_rom(q,WORDS,rom,WORDS*4,&promptr);
	init_big_from_rom(x,WORDS,rom,WORDS*4,&promptr);
	init_big_from_rom(y,WORDS,rom,WORDS*4,&promptr);

/* randomise */
    printf("Enter 9 digit random number seed  = ");
    scanf("%ld",&seed);
    getchar();
    irand(seed);

    ecurve_init(a,b,p,MR_PROJECTIVE);  /* initialise curve */

    g=epoint_init();
    w=epoint_init();

    if (!epoint_set(x,y,0,g)) /* initialise point of order q */
    {
        printf("1. Problem - point (x,y) is not on the curve\n");
        exit(0);
    }

    ecurve_mult(q,g,w);
    if (!point_at_infinity(w))
    {
        printf("2. Problem - point (x,y) is not of order q\n");
        exit(0);
    }

/* generate public/private keys */
    bigrand(q,d);
    ecurve_mult(d,g,g);

    ep=epoint_get(g,x,x); /* compress point */

    printf("public key = %d ",ep);
    otbase58num(mip,x,stdout);

	printf("private key = ");
	otbase58num(mip,d,stdout);

    return 0;
}

void otbase58num(miracl *mip, flash num, FILE *fp) {
	int b;
	char *pchr;
	int digits, i;
	char *miraclAlpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
	char *bitcoinAlpha= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// remember current base, set to 58
	b = mip->IOBASE;
	mip->IOBASE=58;

	// output to temp string, make base58 alphabet translations, then output to file
	digits = cotstr(num, mip->IOBUFF);
	for (i = 0; i < digits; i++) {
		pchr = strchr(miraclAlpha, mip->IOBUFF[i]);
		if (pchr >= miraclAlpha) { // should always be true..
			fputc(bitcoinAlpha[pchr - miraclAlpha], fp);
		}
	}
	fputc('\n', fp);

	// restore base
	mip->IOBASE = b;
}
