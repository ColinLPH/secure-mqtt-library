CC = gcc
CFLAGS = -O3 -march=native -Wall -Wextra -Werror -std=c11 -D_POSIX_C_SOURCE=200809L -Iinclude -Iinternal -MMD -MP
LDFLAGS = -Llib -lsmqtt -lsodium

SRCS = $(wildcard src/*.c internal/*.c)
OBJS = $(patsubst %.c,build/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)

LIB = lib/libsmqtt.a

CLIENT_SRC = samples/client/main.c
CLIENT_BIN = build/samples/client

SMOQER_SRC = samples/smoqer/main.c
SMOQER_BIN = build/samples/smoqer

TEST_SRCS = $(wildcard tests/*.c)
TEST_BINS = $(patsubst tests/%.c,build/tests/%,$(TEST_SRCS))

all: $(LIB)

# ----- library -----

$(LIB): $(OBJS)
	mkdir -p lib
	ar rcs $@ $^

build/%.o: %.c
	mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# ----- samples -----

client: $(CLIENT_BIN)

$(CLIENT_BIN): $(CLIENT_SRC) $(LIB)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

smoqer: $(SMOQER_BIN)

$(SMOQER_BIN): $(SMOQER_SRC) $(LIB)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

samples: client smoqer

# ----- tests -----

tests: $(TEST_BINS)

build/tests/%: tests/%.c $(LIB)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)

# ----- cleanup -----

clean:
	rm -rf build lib/libsmqtt.a

-include $(DEPS)