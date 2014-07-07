#include "tios.h"

// http://www.cemetech.net/forum/viewtopic.php?t=7087

void tios_ClrLCDFull() __naked {
	__asm
		rst #0x28
		.dw #0x4540
		ret
	__endasm;
}

void tios_NewLine() __naked {
	__asm
		rst #0x28
		.dw #0x452E
		ret
	__endasm;
}

void tios_HomeUp() __naked {
	__asm
		rst #0x28
		.dw #0x4558
		ret
	__endasm;
}

void tios_PutS(char *s) {
	s; // warning about unused
	__asm
		ld l,4(ix)
		ld h,5(ix)
		rst #0x28
		.dw #0x450A
	__endasm;
}

void tios_PutC(char c) {
	c; // warning about unused
	__asm
		ld a, 4(ix)
		rst #0x28
		.dw #0x4504
	__endasm;
}
