bitcoingen: bitcoingen.c
	gcc -m64 -O2 -Wall -I MIRACL/pile bitcoingen.c MIRACL/miracl.a -o bitcoingen
