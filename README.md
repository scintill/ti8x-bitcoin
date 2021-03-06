# ti8x-bitcoin

The goal of this project was to get TI-8x calculators doing basic [Bitcoin](https://github.com/bitcoin/bitcoin) operations.  Or probably just generating address keypairs before I lose interest (if I even get that far.)

## Abandonment

I'm calling this semi-abandoned, because I may come back to it, but it's unlikely.  Somebody else has now released a finished keypair generator for TI-89 ([video](https://vimeo.com/123798651), [source](http://www.mattwhitlock.com/diceware/diceware.c)).  I suspect it will take a lot of work to even slim mine down enough, and there is an auditability/proveability advantage in that code for being so tight and self-contained.  (P.S. I am now realizing it was probably silly of me to target "TI8X", as that covers Z80 and m68k, which are quite different.  Perhaps if this m68k code was ported to Z80, it wouldn't be small enough.)

## Why?

[We do what we must because we can](http://www.imdb.com/character/ch0069595/quotes).  My main motivation is just to see if it could be done.  I was inspired by [this Bitcointalk thread](https://bitcointalk.org/index.php?topic=288057.5).  The height of my imagined usefulness for this project would be to make a video of generating keypairs by rolling dice.  In real life, I wouldn't readily trust the derived address without putting the private key into something more sophisticated and verifying the public address output, so why not just generate it there in the first place?

In short, this is intended as a toy proof-of-concept project to have fun with calculator development.

## How?

My current philosophy is to get self-contained C99 code working on Linux, then cross-compile for the calculator with sdcc (testing on my own TI-84+.)  The Linux version seems to work, but I've hit a pretty big problem with the porting: size!  The current Z80 output is ~275K, compared to the theoretical 160K maximum that Texas Instruments says a TI-83+ flash app can be.  I haven't invested a lot of time into shrinking the output yet, and have done nothing at all to deal with a multi-page app on the TI.

For now I'm a bit burned out on this, so I'm just going to release what I have.  See [TODO.md](TODO.md) for some brief notes on where to take this in the future.

Build with `make -f Makefile.linux64` or `make -f Makefile.ti.sdcc`.  Remember to init the git submodule first.  Check TI output size with `make -f Makefile.ti.sdcc sizechk`.

## Build Dependencies
- Tested only on Linux.
- `make`, probably GNU make.
- `gcc` if compiling for Linux.
- [`sdcc`](http://sdcc.sourceforge.net/) (Small Device C Compiler), tested with version 3.4.0.
- Python (for binpac8x.py, but it currently fails anyway with the oversize output)

## Warranty

No warranty!; you're on your own if you actually use keypairs generated by this code.
