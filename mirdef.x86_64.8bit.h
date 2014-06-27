/*
 *   MIRACL compiler/hardware definitions - mirdef.h
 *
 * This is for x86_64 compiled with the small constraints we'll need for TI.
 */
#define MR_LITTLE_ENDIAN
#define MIRACL 8
#define mr_utype char
#define MR_IBITS 32
#define MR_LBITS 64
#define mr_unsign32 unsigned int
#define mr_unsign64 unsigned long
#define mr_dltype short
#define MR_STATIC 32
#define MR_ALWAYS_BINARY
#define MR_NOASM
#define MR_STRIPPED_DOWN
#define MR_NO_STANDARD_IO
#define MR_NO_FILE_IO
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8
#define MR_NO_ECC_MULTIADD
#define MR_NO_RAND
#define MR_NO_SS
