#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miracl.h"
#include "rmd160.h"

#define WORDS 4

// from romaker with secp256k1.ecs
static const mr_small rom[]={
0xfffffffefffffc2f,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,
0xbfd25e8cd0364141,0xbaaedce6af48a03b,0xfffffffffffffffe,0xffffffffffffffff,
0x59f2815b16f81798,0x29bfcdb2dce28d9,0x55a06295ce870b07,0x79be667ef9dcbbac,
0x9c47d08ffb10d4b8,0xfd17b448a6855419,0x5da4fbfc0e1108a8,0x483ada7726a3c465};

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail, FILE *fp);
void otbitcoinaddress(miracl *mip, char compflag, big x, FILE *fp);

int main()
{
	int ep;
	epoint *g,*w;
	big a,b,p,q,x,y,d;
	long seed;
	int promptr;
	miracl *mip;

	mip = mirsys(38,256); // 38 bytes = 32 key + 1 lead + 1 trail + 4 checksum
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

	// randomise
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

	// generate public/private keys
	bigrand(q,d);
	ecurve_mult(d,g,g);

	ep=epoint_get(g,x,x); /* compress point */

	printf("public address = ");
	otbitcoinaddress(mip, ep, x, stdout);

	printf("private WIF = ");
	otbase58num(mip, 32, '\x80', d, '\x01', stdout);

	// free and scrub
	mirkill(d);
	mirkill(x);
	mirkill(y);
	mirkill(p);
	mirkill(a);
	mirkill(b);
	mirkill(q);
	epoint_free(g);
	epoint_free(w);

	mirexit();

	return 0;
}

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail, FILE *fp) {
	int digits, i, j;
	char *buff;
	int buffsize;
	sha256 s256;
	char hash[32];
	big binnum;

	char *pchr;
	char *miraclAlpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
	char *bitcoinAlpha= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

	// make temp buffer: lead+num+trail+(checksum)
	buffsize = 1 + num_bytes + (trail ? 1:0) + 4;
	buff = malloc(buffsize);
	buff[0] = lead;
	i = 1 + big_to_bytes(num_bytes, num, &buff[1], TRUE);

	if (trail) {
		buff[i++] = trail;
	}

	// double-sha256 buff[0..(i-1)] for checksum
	shs256_init(&s256);
	for (j = 0; j < i; j++) {
		shs256_process(&s256, buff[j]);
	}
	shs256_hash(&s256, hash);

	shs256_init(&s256);
	for (j = 0; j < sizeof(hash); j++) {
		shs256_process(&s256, hash[j]);
	}
	shs256_hash(&s256, hash);

	// append checksum
	buff[i++] = hash[0];
	buff[i++] = hash[1];
	buff[i++] = hash[2];
	buff[i++] = hash[3];

	// put result into bignum so we can base58 it
	binnum = mirvar(0);
	bytes_to_big(i, buff, binnum);

	// front-pad with "zero" digits
	for (j = 0; buff[j] == 0 && j < i; j++) {
		fputc(bitcoinAlpha[0], fp);
	}

	free(buff);

	// output to temp string, make base58 alphabet translations, output to file
	mip->IOBASE=58;
	digits = cotstr(binnum, mip->IOBUFF);
	mirkill(binnum);
	for (j = 0; j < digits; j++) {
		pchr = strchr(miraclAlpha, mip->IOBUFF[j]);
		if (pchr >= miraclAlpha) { // should always be true..
			fputc(bitcoinAlpha[pchr - miraclAlpha], fp);
		}
	}
	fputc('\n', fp);
}

void otbitcoinaddress(miracl *mip, char compflag, big x, FILE *fp) {
	char buff[33];
	sha256 s256;
	unsigned char sha256[32];

	mr_unsign32 MDbuf[5];
	unsigned int i;
	char rmd160[20];

	big binnum;

	// prepend flag
	buff[0] = '\x02' + compflag;
	big_to_bytes(32, x, &buff[1], TRUE);

	// sha256
	shs256_init(&s256);
	for (i = 0; i < sizeof(buff); i++) {
		shs256_process(&s256, buff[i]);
	}
	shs256_hash(&s256, (char*)sha256);

	// ripemd160
	MDinit(MDbuf);
	MDfinish(MDbuf, sha256, 32, 0);
	for (i = 0; i < sizeof(rmd160); i += 4) {
		rmd160[i]   =  MDbuf[i>>2];         /* implicit cast to byte  */
		rmd160[i+1] = (MDbuf[i>>2] >>  8);  /*  extracts the 8 least  */
		rmd160[i+2] = (MDbuf[i>>2] >> 16);  /*  significant bits. */
		rmd160[i+3] = (MDbuf[i>>2] >> 24);
	}

	// bignum
	binnum = mirvar(0);
	bytes_to_big(sizeof(rmd160), rmd160, binnum);

	// base58
	otbase58num(mip, sizeof(rmd160), '\x00', binnum, 0, fp);

	// cleanup
	mirkill(binnum);
}
