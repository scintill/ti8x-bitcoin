#include <stdlib.h>
#include <string.h>

#include "miracl.h"
#include "rmd160.h"

#ifdef TI8X
#include "tiglue.h"
#else /* TI8X */
#include <stdio.h>
#endif

// from romaker with secp256k1.ecs
static const mr_small rom[]={
0x2f,0xfc,0xff,0xff,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0x41,0x41,0x36,0xd0,0x8c,0x5e,0xd2,0xbf,0x3b,0xa0,0x48,0xaf,0xe6,0xdc,0xae,0xba,0xfe,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
0x98,0x17,0xf8,0x16,0x5b,0x81,0xf2,0x59,0xd9,0x28,0xce,0x2d,0xdb,0xfc,0x9b,0x2,0x7,0xb,0x87,0xce,0x95,0x62,0xa0,0x55,0xac,0xbb,0xdc,0xf9,0x7e,0x66,0xbe,0x79,
0xb8,0xd4,0x10,0xfb,0x8f,0xd0,0x47,0x9c,0x19,0x54,0x85,0xa6,0x48,0xb4,0x17,0xfd,0xa8,0x8,0x11,0xe,0xfc,0xfb,0xa4,0x5d,0x65,0xc4,0xa3,0x26,0x77,0xda,0x3a,0x48};

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail);
void otbitcoinaddress(miracl *mip, char compflag, big x);

int main()
{
	int lsby;
	epoint *g, *w;
	big a, b, p, q, x, y, d;
	int promptr;
	miracl *mip;
	char stallocbn[MR_BIG_RESERVE(7)] = {0};
	char stallocep[MR_ECP_RESERVE(2)] = {0};

#ifdef TI8X
	tios_ClrLCDFull();
	tios_HomeUp();
#endif
	puts("Hello..");

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
		puts("1. Problem - point (x,y) is not on the curve");
		mirexit();
		return 1;
	}

	ecurve_mult(q, g, w);
	if (!point_at_infinity(w))
	{
		puts("2. Problem - point (x,y) is not of order q");
		mirexit();
		return 2;
	}

	// generate public/private keys
	// TODO input private key material
	convert(1, d);
	ecurve_mult(d, g, g);

	lsby = epoint_get(g, x, x); // compress point

	fputs("public address = ", stdout);
	otbitcoinaddress(mip, lsby, x);

	fputs("private WIF = ", stdout);
	otbase58num(mip, 32, '\x80', d, '\x01');

	// free and scrub
	memset(stallocbn, 0, sizeof(stallocbn));
	memset(stallocep, 0, sizeof(stallocep));

	mirexit();

	return 0;
}

void otbase58num(miracl *mip, unsigned int num_bytes, char lead, big num, char trail) {
	unsigned int digits, i, j;
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
		putchar(bitcoinAlpha[0]);
	}

	// output to temp string, make base58 alphabet translations, output to file
	mip->IOBASE = 58;
	digits = cotstr(binnum, mip->IOBUFF);
	memset(stalloc, 0, sizeof(stalloc));
	for (j = 0; j < digits; j++) {
		pchr = strchr(miraclAlpha, mip->IOBUFF[j]);
		if (pchr >= miraclAlpha) { // should always be true..
			putchar(bitcoinAlpha[pchr - miraclAlpha]);
		}
	}
	putchar('\n');
}

void otbitcoinaddress(miracl *mip, char compflag, big x) {
	char buff[33];
	sha256 s256;
	char stalloc[MR_BIG_RESERVE(1)] = {0};

	hash_state rmds;
	unsigned int i;

	big binnum;

	// prepend flag
	buff[0] = '\x02' + compflag;
	big_to_bytes(32, x, &buff[1], TRUE);

	// sha256
	shs256_init(&s256);
	for (i = 0; i < sizeof(buff); i++) {
		shs256_process(&s256, buff[i]);
	}
	shs256_hash(&s256, (char *)rmds.rmd160.buf.buf8); // store straight into rmd160 input buffer

	// ripemd160
	rmd160_init(&rmds);
	// from the finalization function originally
	i = 32; // size of sha256 hash
	/* append the '1' bit */
	rmds.rmd160.buf.buf8[i++] = (unsigned char)0x80;
	/* pad upto 56 bytes of zeroes */
	while (i < 56) {
		rmds.rmd160.buf.buf8[i++] = (unsigned char)0;
	}
	/* store length */
	rmds.rmd160.buf.buf32[14] = 32 * 8;
	rmds.rmd160.buf.buf32[15] = 0;
	rmd160_compress(&rmds, rmds.rmd160.buf.buf8);

	// bignum
	binnum = mirvar_mem(stalloc, 0);
	bytes_to_big(sizeof(rmds.rmd160.out), (char *)rmds.rmd160.out, binnum);

	// base58
	otbase58num(mip, sizeof(rmds.rmd160.out), '\x00', binnum, 0);

	// cleanup
	memset(stalloc, 0, sizeof(stalloc));
	memset(buff, 0, sizeof(buff));
}
