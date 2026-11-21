CFLAGS	= -Wall -Wextra -Wpedantic -std=c11

.PHONY: all clean

all: build/example1 build/example2 build/example3
build/example1: example1.c
	mkdir -p build
	gcc $(CFLAGS) example1.c -lccth -o build/example1 
build/example2: example2.c
	mkdir -p build
	gcc $(CFLAGS) example2.c -lccth -o build/example2 
build/example3: example3.c
	mkdir -p build
	gcc $(CFLAGS) example3.c -lccth -o build/example3
clean:
	rm -rf build
