bitcoingen: bitcoingen.c rmd160.o
	gcc -m64 -O2 -Wall -I MIRACL/pile bitcoingen.c rmd160.o MIRACL/miracl.a -o bitcoingen

rmd160.o: rmd160.c rmd160.h
	gcc -m64 -O2 -Wall -I MIRACL/pile rmd160.c -c -o rmd160.o

valgrind: bitcoingen
	valgrind --leak-check=full --show-reachable=yes --gen-suppressions=yes ./bitcoingen
	valgrind --tool=exp-sgcheck ./bitcoingen
