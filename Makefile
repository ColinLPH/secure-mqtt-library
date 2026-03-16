CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c11 -Iinclude -Iinternal -MMD -MP
LDFLAGS = -Llib -lsmqtt -lsodium   # <-- add -lsodium here

SRCS = $(wildcard src/*.c internal/*.c)
OBJS = $(patsubst %.c,build/%.o,$(SRCS))
DEPS = $(OBJS:.o=.d)

LIB = lib/libsmqtt.a

CLIENT_SRC = samples/client/main.c
CLIENT_BIN = build/samples/client

SMOQER_SRC = samples/smoqer/main.c
SMOQER_BIN = build/samples/smoqer

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
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

smoqer: $(SMOQER_BIN)

$(SMOQER_BIN): $(SMOQER_SRC) $(LIB)
	mkdir -p $(@D)
	$(CC) $(CFLAGS) $< $(LDFLAGS) -o $@

samples: client smoqer

# ----- cleanup -----

clean:
	rm -rf build lib/libsmqtt.a

-include $(DEPS)