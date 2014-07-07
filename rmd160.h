#ifndef RMD160_H
#define RMD160_H

#include "mirdef.h" /* portable type defines */

typedef struct {
	struct rmd160 {
		unsigned char length;
		union {
			unsigned char buf8[64];
			mr_unsign32 buf32[16];
		} buf;
		mr_unsign32 curlen, out[5];
	} rmd160;
} hash_state;

void rmd160_compress(hash_state *md, unsigned char *buf);
void rmd160_init(hash_state *md);
void rmd160_done(hash_state *md);

#endif /* RMD160_H */
