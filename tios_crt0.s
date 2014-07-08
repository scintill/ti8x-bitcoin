; © 2014 Joey Hewitt.  See COPYING.txt for terms.

; tios_crt0.s - TIOS assembly program header 
; http://www.cemetech.net/forum/viewtopic.php?t=7087 may be helpful
   .module crt 
   .globl _main 
   .area _HEADER (ABS) 
   .org #0x9D93 
   .dw #0x6DBB 
   call gsinit 
   jp _main 
   .org 0x9D9B 
   .area _HOME 
   .area _CODE 
   .area _GSINIT 
   .area _GSFINAL 
   .area _DATA 
   .area _BSEG 
   .area _BSS 
   .area _HEAP 
   .area _CODE 
   ;; Twice ??? 

__clock:: 
   ld a,#2 
   ret ; needed somewhere... 
    
   .area _GSINIT 
gsinit:: 
   .area _GSFINAL 
   ret 
