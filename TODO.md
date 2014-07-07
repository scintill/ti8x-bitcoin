- Check out why the local bignum vars in bitcoingen.c generate so much code to allocate. Use static-storage vars instead of stack space?  Maybe ask TIOS for RAM (if possible) instead of static/stack?

- Inline the TI stubs and my wrappers - the actual TI call is only 3 bytes, so the current output is pretty wasteful.  On the other hand, there are much bigger (in literal code size) problems.

- Restructure as a collection of small ASM programs that can fit in 16K (flash page) each?  Make the main keypair program be a BASIC program that calls each subprogram for the different operations: create bignum private key, do EC multiplication, RIPEMD hash, base58-encode, etc.

- If splitting into separate programs, we might be able to get it all on the device at once, and the individual pieces could at least be tested.  Worst case, we might need to tether to PC and push individual pieces in and out.

- We're always going to have to deal with 32-bit (or higher) math, which is going to bloat into a lot of Z80 instructions... can we use some TIOS calls or our own subroutines to make this smaller?  It might then be really slow, but small enough.

- The TI build produces a lot of compiler warnings that sound pretty scary (like the output may be completely broken), such as "Non-connected liverange found and extended to connected component of the CFG:iTemp141. Please contact sdcc authors with source code to reproduce."; "integer constant '0xb5c0fbcfL' out of range, truncated to 2147483647"; "right shifting more than size of object changed to zero". I have not looked closely or tested at all.

- May need to manually trim MIRACL objects, if the SDCC linker isn't able to throw out unused functions.