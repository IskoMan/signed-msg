CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Werror
CPPFLAGS = -Iinclude
SAN      = -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g -O1

SRC  = src/sha256.c src/signed_msg.c
TEST = test/test_main.c

.PHONY: all test asan clean

all: build/libsigned_msg.a

build:
	mkdir -p build

build/libsigned_msg.a: $(SRC) include/*.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c src/sha256.c -o build/sha256.o
	$(CC) $(CPPFLAGS) $(CFLAGS) -c src/signed_msg.c -o build/signed_msg.o
	ar rcs $@ build/sha256.o build/signed_msg.o

build/test: $(SRC) $(TEST) include/*.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) $(TEST) -o $@

build/test-asan: $(SRC) $(TEST) include/*.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SAN) $(SRC) $(TEST) -o $@

test: build/test
	./build/test

# AddressSanitizer + UndefinedBehaviorSanitizer; any finding aborts the run.
asan: build/test-asan
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 UBSAN_OPTIONS=print_stacktrace=1 ./build/test-asan

clean:
	rm -f build/*.o build/*.a build/test build/test-asan
