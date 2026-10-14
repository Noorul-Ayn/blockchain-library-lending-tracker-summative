# Blockchain Library Lending Tracker (summative) - build file
#
#   make          build ./library_tracker
#   make run      build and run
#   make test     build and run the automated end-to-end tests
#   make debug    build with AddressSanitizer + UndefinedBehaviorSanitizer
#   make clean    remove build output

CC       ?= gcc
TARGET   := library_tracker
SRC_DIR  := src
INC_DIR  := include
OBJ_DIR  := build

CPPFLAGS += -I$(INC_DIR) -D_POSIX_C_SOURCE=200809L -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2
CFLAGS   ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wformat=2 \
            -Wstrict-prototypes -Wmissing-prototypes -fstack-protector-strong
LDLIBS   += -lcrypto -lm

SRCS := $(wildcard $(SRC_DIR)/*.c)
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all run test debug clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

run: $(TARGET)
	./$(TARGET)

test: $(TARGET)
	./tests/run_tests.sh

debug: clean
	$(MAKE) CFLAGS="-std=c11 -g -O1 -Wall -Wextra -Wpedantic -fsanitize=address,undefined -fno-omit-frame-pointer" \
	        LDFLAGS="-fsanitize=address,undefined"

clean:
	rm -rf $(OBJ_DIR) $(TARGET)

-include $(DEPS)
