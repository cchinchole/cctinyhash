CFLAGS	= -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean

all: build/example1 build/example2
build/example1: example1.c
	mkdir -p build
	gcc $(CFLAGS) example1.c -lccth -o build/example1 
build/example2: example2.c
	mkdir -p build
	gcc $(CFLAGS) example2.c -lccth -o build/example2 
clean:
	rm -rf build
