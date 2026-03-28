SRC_DIR := src
INCLUDE_DIR := include
OBJ_DIR := obj
BUILD_DIR := build
TEST_DIR := test

CC := gcc
CFLAGS := -Wall -Wextra -Wpedantic -I$(INCLUDE_DIR) -O2
LDFLAGS := -lgmp

PHASE1_SRCS := phase1.c rsa_tools.c other_base64.c utility.c phase1_test.c test_utility.c bezout.c
PHASE2_SRCS := phase2.c rsa_tools.c utility.c phase2_test.c test_utility.c other_base64.c bezout.c

PHASE1_OBJS := $(patsubst %.c, $(OBJ_DIR)/%.o, $(PHASE1_SRCS))
PHASE2_OBJS := $(patsubst %.c, $(OBJ_DIR)/%.o, $(PHASE2_SRCS))

PHASE1_TEST := $(BUILD_DIR)/phase1_test
PHASE2_TEST := $(BUILD_DIR)/phase2_test

PHASE3_SRCS := phase3.c phase2.c rsa_tools.c other_base64.c utility.c bezout.c
PHASE3_OBJS := $(patsubst %.c, $(OBJ_DIR)/%.o, $(PHASE3_SRCS))
PHASE3 := $(BUILD_DIR)/phase3

phase1: $(PHASE1_TEST)
phase2: $(PHASE2_TEST)
phase3: $(PHASE3)

$(PHASE1_TEST): $(PHASE1_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(PHASE2_TEST): $(PHASE2_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(PHASE3): $(PHASE3_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJ_DIR)/%.o: $(TEST_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR)/*.o $(BUILD_DIR)/*