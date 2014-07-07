#ifndef TIGLUE_H
#define TIGLUE_H

#include "tios.h"
#define stdout 0
int puts(char *s) {
	tios_PutS(s);
	tios_NewLine();
	return 0;
}
int fputs(char *s, void *fp) {
	fp; // unused
	tios_PutS(s);
	return 0;
}
int putchar(char c) {
	tios_PutC(c);
	return c;
}

#endif /* TIGLUE_H */
