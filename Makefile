bitcoingen: bitcoingen.c
	gcc -m64 -O2 -Wall -I MIRACL/pile bitcoingen.c MIRACL/miracl.a -o bitcoingen

valgrind: bitcoingen
	valgrind --leak-check=full --show-reachable=yes --gen-suppressions=yes ./bitcoingen
	valgrind --tool=exp-sgcheck ./bitcoingen
