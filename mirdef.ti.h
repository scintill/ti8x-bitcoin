/*
 * MIRACL compiler/hardware definitions - mirdef.h
 *
 * for Z80 on sdcc, based on Atmeg128 file
 */

#define MR_LITTLE_ENDIAN
#define MIRACL 8
#define mr_utype char /* wordlength of processor */
#define MR_IBITS 16  /* number of bits in int  */
#define MR_LBITS 32  /* number of bits in long */
#define mr_unsign32 unsigned long /* unsigned 32-bit type */
#define mr_unsign64 unsigned long long
#define mr_dltype short /* double-length type (twice the number of bits of mr_utype) */
#define MR_STATIC 32
#define MR_ALWAYS_BINARY
#define MR_NOASM     /* no assembly language */
#define MR_STRIPPED_DOWN
#define MR_NO_STANDARD_IO /* no printf support */
#define MR_NO_FILE_IO     /* no file support */
#define MAXBASE ((mr_small)1<<(MIRACL-1))
#define MR_BITSINCHAR 8
#define MR_NO_ECC_MULTIADD
#define MR_NO_RAND
#define MR_NO_SS
#define MR_SHORT_OF_MEMORY