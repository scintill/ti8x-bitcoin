#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miracl.h"
#include "rmd160.h"

// from romaker with secp256k1.ecs
static const mr_unsign64 rom[]={
0xfffffffefffffc2f,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,
0xbfd25e8cd0364141,0xbaaedce6af48a03b,0xfffffffffffffffe,0xffffffffffffffff,
0x59f2815b16f81798,0x29bfcdb2dce28d9,0x55a06295ce870b07,0x79be667ef9dcbbac,
0x9c47d08ffb10d4b8,0xfd17b448a6855419,0x5da4fbfc0e1108a8,0x483ada7726a3c465};

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail, FILE *fp);
void otbitcoinaddress(miracl *mip, char compflag, big x, FILE *fp);

int main()
{
	int lsby;
	epoint *g, *w;
	big a, b, p, q, x, y, d;
	int promptr;
	miracl *mip;
	char stallocbn[MR_BIG_RESERVE(7)] = {0};
	char stallocep[MR_ECP_RESERVE(2)] = {0};

	mip = mirsys(MR_STATIC, 0);
	p = mirvar_mem(stallocbn, 0);
	a = mirvar_mem(stallocbn, 1);
	b = mirvar_mem(stallocbn, 2);
	convert(7, b);
	q = mirvar_mem(stallocbn, 3);
	x = mirvar_mem(stallocbn, 4);
	y = mirvar_mem(stallocbn, 5);
	d = mirvar_mem(stallocbn, 6);

	promptr = 0;
	init_big_from_rom(p, 4*8, (void*)rom, 4*8*4, &promptr);
	init_big_from_rom(q, 4*8, (void*)rom, 4*8*4, &promptr);
	init_big_from_rom(x, 4*8, (void*)rom, 4*8*4, &promptr);
	init_big_from_rom(y, 4*8, (void*)rom, 4*8*4, &promptr);

	ecurve_init(a, b, p, MR_PROJECTIVE);  // initialise curve

	g = epoint_init_mem(stallocep, 0);
	w = epoint_init_mem(stallocep, 1);

	if (!epoint_set(x, y, 0, g)) // initialise point of order q
	{
		printf("1. Problem - point (x,y) is not on the curve\n");
		exit(0);
	}

	ecurve_mult(q, g, w);
	if (!point_at_infinity(w))
	{
		printf("2. Problem - point (x,y) is not of order q\n");
		exit(0);
	}

	// generate public/private keys
	// TODO input private key material
	convert(1, d);
	ecurve_mult(d, g, g);

	lsby = epoint_get(g, x, x); // compress point

	printf("public address = ");
	otbitcoinaddress(mip, lsby, x, stdout);

	printf("private WIF = ");
	otbase58num(mip, 32, '\x80', d, '\x01', stdout);

	// free and scrub
	memset(stallocbn, 0, sizeof(stallocbn));
	memset(stallocep, 0, sizeof(stallocep));

	mirexit();

	return 0;
}

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail, FILE *fp) {
	int digits, i, j;
	char buff[1 + 32 + 1 + 4]; // lead+num+trail+(checksum)
	sha256 s256;
	char hash[32];
	big binnum;
	char stalloc[MR_BIG_RESERVE(1)] = {0};

	char *pchr;
	const char *miraclAlpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuv";
	const char *bitcoinAlpha= "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

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
	binnum = mirvar_mem(stalloc, 0);
	bytes_to_big(i, buff, binnum);

	// front-pad with "zero" digits
	for (j = 0; buff[j] == 0 && j < i; j++) {
		fputc(bitcoinAlpha[0], fp);
	}

	// output to temp string, make base58 alphabet translations, output to file
	mip->IOBASE=58;
	digits = cotstr(binnum, mip->IOBUFF);
	memset(stalloc, 0, sizeof(stalloc));
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
	char stalloc[MR_BIG_RESERVE(1)] = {0};

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
		rmd160[i]   =  MDbuf[i>>2];         // implicit cast to byte
		rmd160[i+1] = (MDbuf[i>>2] >>  8);  //  extracts the 8 least
		rmd160[i+2] = (MDbuf[i>>2] >> 16);  //  significant bits.
		rmd160[i+3] = (MDbuf[i>>2] >> 24);
	}

	// bignum
	binnum = mirvar_mem(stalloc, 0);
	bytes_to_big(sizeof(rmd160), rmd160, binnum);

	// base58
	otbase58num(mip, sizeof(rmd160), '\x00', binnum, 0, fp);

	// cleanup
	memset(stalloc, 0, sizeof(stalloc));
	memset(buff, 0, sizeof(buff));
}
