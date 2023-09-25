all: rdtsc sldt-zf str-zf rdpmc rdfsbase rdgsbase

sldt-zf: sldt-zf.c cacheutils.h
	gcc sldt-zf.c -static -o sldt-zf

str-zf: str-zf.c cacheutils.h
	gcc str-zf.c -static -o str-zf

rdfsbase: rdfsbase.c cacheutils.h
	gcc rdfsbase.c -static -o rdfsbase

rdgsbase: rdgsbase.c cacheutils.h
	gcc rdgsbase.c -static -o rdgsbase

rdtsc: rdtsc.c cacheutils_t.h
	gcc rdtsc.c -Os -o rdtsc -march=native -mavx2 -pthread

rdpmc: rdpmc.c cacheutils.h
	gcc rdpmc.c -Os -o rdpmc -march=native

clean:
	rm -f sldt-zf str-zf rdtsc rdpmc rdfsbase rdgsbase
	
