CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic -std=c11
CPPFLAGS ?= -Iinclude
LDFLAGS ?=
LDLIBS ?= -lcrypto

SRC = src/railgun_kohaku.c
TEST = tests/test_railgun_kohaku.c

all: test_railgun_kohaku

test_railgun_kohaku: $(SRC) $(TEST) include/railgun_kohaku.h
	$(CC) $(CFLAGS) $(CPPFLAGS) $(SRC) $(TEST) $(LDFLAGS) $(LDLIBS) -o $@

test: test_railgun_kohaku
	./test_railgun_kohaku

clean:
	rm -f test_railgun_kohaku

.PHONY: all test clean
