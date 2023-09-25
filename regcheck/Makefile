all: meltdown-3a-checker

meltdown-3a-checker: main.c cacheutils.h
	gcc main.c -static -o regcheck-checker -pthread

clean:
	rm -f regcheck-checker
	
